import torch
from transformers import DistilBertTokenizer, DistilBertForMaskedLM, Trainer, TrainingArguments, DataCollatorForLanguageModeling
from torch.utils.data import Dataset
import sys
import os
import random

class RequestDataset(Dataset):
    def __init__(self, tokenizer, file_path, block_size=128):
        self.examples = []
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            
        # We treat each line (request) as a separate sample.
        # We want to tokenize it and add special tokens [CLS] ... [SEP]
        print(f"Tokenizing {len(lines)} requests...")
        for line in lines:
            line = line.strip()
            if not line: continue
            
            # Encodes adds [CLS] and [SEP] automatically
            tokenized = tokenizer(line, truncation=True, max_length=block_size, padding="max_length")
            self.examples.append({
                "input_ids": torch.tensor(tokenized["input_ids"]),
                "attention_mask": torch.tensor(tokenized["attention_mask"])
            })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, item):
        return self.examples[item]

def train_model(train_file="benign_traffic.txt", output_dir="./waf_model"):
    print(f"Loading data from {train_file}...")
    
    tokenizer = DistilBertTokenizer.from_pretrained('distilbert-base-uncased')
    
    # Create full dataset
    full_dataset = RequestDataset(tokenizer, train_file)
    
    # Split into Train (90%) and Val (10%)
    train_size = int(0.9 * len(full_dataset))
    val_size = len(full_dataset) - train_size
    train_dataset, val_dataset = torch.utils.data.random_split(full_dataset, [train_size, val_size])
    
    print(f"Training on {len(train_dataset)} samples, Validating on {len(val_dataset)} samples")
    
    model = DistilBertForMaskedLM.from_pretrained('distilbert-base-uncased')
    
    training_args = TrainingArguments(
        output_dir=output_dir,
        overwrite_output_dir=True,
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        save_steps=500,
        save_total_limit=2,
        evaluation_strategy="epoch",  # Evaluate every epoch
        logging_dir='./logs',
        logging_steps=50,
        load_best_model_at_end=True,
        metric_for_best_model="loss"
    )
    
    data_collator = DataCollatorForLanguageModeling(
        tokenizer=tokenizer, mlm=True, mlm_probability=0.15
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        data_collator=data_collator,
        train_dataset=train_dataset,
        eval_dataset=val_dataset,
    )
    
    print("Starting training...")
    trainer.train()
    
    print(f"Saving BEST model to {output_dir}")
    trainer.save_model(output_dir)
    tokenizer.save_pretrained(output_dir)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        train_file = sys.argv[1]
    else:
        train_file = "benign_traffic.txt"
        
    if not os.path.exists(train_file):
        print(f"Error: {train_file} not found. Generate traffic first!")
        sys.exit(1)
        
    train_model(train_file)
