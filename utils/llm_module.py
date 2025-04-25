import os
import torch
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Tuple
from transformers import (
    AutoModelForSeq2SeqLM, 
    AutoTokenizer, 
    TrainingArguments, 
    Trainer, 
    DataCollatorForSeq2Seq
)
from datasets import Dataset, load_dataset
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split

# Import project config
import sys
sys.path.append(str(Path(__file__).parent.parent))
from config import config, MODEL_DIR, DATA_DIR

# Set up logging
logger = logging.getLogger(__name__)

class CybersecurityLLM:
    """
    Handles training and inference for the LLM-powered cybersecurity assistant
    """
    
    def __init__(self, model_name: Optional[str] = None):
        """Initialize the LLM with either a pre-trained model or a fine-tuned one"""
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        logger.info(f"Using device: {self.device}")
        
        # Use provided model name or default from config
        self.model_name = model_name or config["llm"]["base_model"]
        self.max_length = config["llm"]["max_length"]
        self.temperature = config["llm"]["temperature"]
        
        # Check if fine-tuned model exists
        self.fine_tuned_path = Path(config["llm"]["model_path"])
        if self.fine_tuned_path.exists() and list(self.fine_tuned_path.glob("*")):
            logger.info(f"Loading fine-tuned model from {self.fine_tuned_path}")
            self.model = AutoModelForSeq2SeqLM.from_pretrained(
                str(self.fine_tuned_path), device_map=self.device
            )
            self.tokenizer = AutoTokenizer.from_pretrained(str(self.fine_tuned_path))
        else:
            logger.info(f"Loading base model: {self.model_name}")
            self.model = AutoModelForSeq2SeqLM.from_pretrained(self.model_name, device_map=self.device)
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
    
    def generate_response(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Generate a response to a cybersecurity query"""
        try:
            # Format input with context if provided
            if context:
                input_text = f"Question: {query}\nContext: {context}\nAnswer:"
            else:
                input_text = f"Question: {query}\nAnswer:"
            
            # Tokenize and generate
            inputs = self.tokenizer(
                input_text, 
                return_tensors="pt", 
                max_length=self.max_length, 
                truncation=True
            ).to(self.device)
            
            # Generate response
            outputs = self.model.generate(
                inputs["input_ids"],
                max_length=self.max_length,
                temperature=self.temperature,
                do_sample=True,
                top_p=0.95,
            )
            
            # Decode and return
            response = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            # Calculate confidence score (placeholder - would be model-specific)
            confidence = 0.85  # Placeholder - would extract from model outputs
            
            return {
                "answer": response,
                "confidence": confidence,
                "references": []  # Would populate with relevant sources
            }
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            return {
                "answer": "I encountered an error processing your request.",
                "confidence": 0.0,
                "error": str(e)
            }
    
    def prepare_dataset(self, dataset_path: Union[str, Path]) -> Dataset:
        """Prepare a dataset for training"""
        try:
            # Load the dataset (CSV, JSON, etc.)
            data_path = Path(dataset_path)
            
            if data_path.suffix == '.csv':
                df = pd.read_csv(data_path)
            elif data_path.suffix == '.json':
                df = pd.read_json(data_path)
            else:
                raise ValueError(f"Unsupported file format: {data_path.suffix}")
            
            # Expect columns 'input' and 'output'
            if 'input' not in df.columns or 'output' not in df.columns:
                raise ValueError("Dataset must contain 'input' and 'output' columns")
            
            # Convert to HF dataset
            dataset = Dataset.from_pandas(df)
            
            # Tokenize the dataset
            def tokenize_function(examples):
                model_inputs = self.tokenizer(
                    examples["input"], 
                    max_length=self.max_length,
                    truncation=True,
                    padding="max_length"
                )
                labels = self.tokenizer(
                    examples["output"],
                    max_length=self.max_length,
                    truncation=True,
                    padding="max_length"
                )
                model_inputs["labels"] = labels["input_ids"]
                return model_inputs
            
            # Apply tokenization
            tokenized_dataset = dataset.map(
                tokenize_function, 
                batched=True,
                remove_columns=dataset.column_names
            )
            
            return tokenized_dataset
        except Exception as e:
            logger.error(f"Error preparing dataset: {str(e)}")
            raise
    
    def fine_tune(
        self, 
        dataset_path: Union[str, Path],
        output_dir: Optional[Union[str, Path]] = None,
        epochs: int = 3,
        batch_size: int = 8,
        learning_rate: float = 5e-5
    ) -> None:
        """Fine-tune the model on cybersecurity data"""
        try:
            # Prepare the dataset
            dataset = self.prepare_dataset(dataset_path)
            
            # Split into train and validation
            dataset_dict = dataset.train_test_split(test_size=0.1)
            
            # Set up training arguments
            training_args = TrainingArguments(
                output_dir=output_dir or str(MODEL_DIR / "checkpoints"),
                per_device_train_batch_size=batch_size,
                per_device_eval_batch_size=batch_size,
                learning_rate=learning_rate,
                num_train_epochs=epochs,
                weight_decay=0.01,
                save_strategy="epoch",
                evaluation_strategy="epoch",
                load_best_model_at_end=True,
                push_to_hub=False
            )
            
            # Create data collator
            data_collator = DataCollatorForSeq2Seq(
                tokenizer=self.tokenizer,
                model=self.model,
                padding=True
            )
            
            # Initialize trainer
            trainer = Trainer(
                model=self.model,
                args=training_args,
                train_dataset=dataset_dict["train"],
                eval_dataset=dataset_dict["test"],
                data_collator=data_collator,
                tokenizer=self.tokenizer,
            )
            
            # Train the model
            logger.info("Starting fine-tuning process...")
            trainer.train()
            
            # Save the fine-tuned model
            final_output_dir = output_dir or str(self.fine_tuned_path)
            logger.info(f"Saving fine-tuned model to {final_output_dir}")
            trainer.save_model(final_output_dir)
            self.tokenizer.save_pretrained(final_output_dir)
            
            logger.info("Fine-tuning complete!")
            
        except Exception as e:
            logger.error(f"Error during fine-tuning: {str(e)}")
            raise

# Helper function to create an instance
def get_llm_instance():
    """Get a singleton instance of the CybersecurityLLM class"""
    return CybersecurityLLM()