"""Optional CTI-BERT semantic classifier for cyber threat reports.

The baseline TF-IDF model remains the production fallback. CTI-BERT is loaded
only when ENABLE_TRANSFORMER=1, then compares contextual text embeddings with
cyber-specific class prototypes. The validation set is never used here.
"""

import os
import threading
from datetime import datetime, timezone

MODEL_NAME = os.getenv("CTI_BERT_MODEL", "ibm-research/CTI-BERT")
MAX_LENGTH = int(os.getenv("CTI_BERT_MAX_LENGTH", "256"))

CLASS_PROTOTYPES = {
    "phishing": [
        "A deceptive email impersonates a trusted company and asks the victim to click a link and enter login credentials.",
        "A fake banking security alert creates urgency and directs the user to verify an account or reset a password.",
        "A prize, invoice, package delivery, subscription, or payment message requests personal or financial information.",
    ],
    "vulnerability": [
        "A CVE describes a software vulnerability, affected product versions, severity, CVSS score, patch, and remediation.",
        "A security flaw permits remote code execution, information disclosure, denial of service, authentication bypass, or privilege escalation.",
        "A vendor advisory explains vulnerable components, exploitation conditions, updates, and mitigations.",
    ],
    "attack_technique": [
        "A threat actor uses a MITRE ATT&CK technique for persistence, discovery, execution, defense evasion, or credential access.",
        "An adversary performs lateral movement, command and control, data collection, exfiltration, or privilege escalation.",
        "A campaign or malware operation describes attacker behavior, tactics, techniques, and procedures.",
    ],
}

_lock = threading.Lock()
_classifier = None
_load_error = None


class CTIBERTSemanticClassifier:
    def __init__(self):
        import torch
        from transformers import AutoModel, AutoTokenizer

        self.torch = torch
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        offline = os.getenv("CTI_BERT_OFFLINE", "0") == "1"
        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, local_files_only=offline)
        self.model = AutoModel.from_pretrained(MODEL_NAME, local_files_only=offline).to(self.device)
        self.model.eval()
        self.labels = list(CLASS_PROTOTYPES)
        self.prototype_embeddings = {
            label: self.encode(texts) for label, texts in CLASS_PROTOTYPES.items()
        }

    def encode(self, texts):
        torch = self.torch
        encoded = self.tokenizer(
            list(texts), padding=True, truncation=True, max_length=MAX_LENGTH,
            return_tensors="pt"
        )
        encoded = {key: value.to(self.device) for key, value in encoded.items()}
        with torch.inference_mode():
            hidden = self.model(**encoded).last_hidden_state
            mask = encoded["attention_mask"].unsqueeze(-1).expand(hidden.size()).float()
            pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9)
            return torch.nn.functional.normalize(pooled, p=2, dim=1)

    def predict_batch(self, texts):
        torch = self.torch
        embeddings = self.encode(texts)
        class_scores = []
        for label in self.labels:
            similarities = embeddings @ self.prototype_embeddings[label].T
            class_scores.append(similarities.max(dim=1).values)
        raw_scores = torch.stack(class_scores, dim=1)
        probabilities = torch.softmax(raw_scores / 0.08, dim=1)
        best = probabilities.argmax(dim=1)
        output = []
        for row_index, label_index in enumerate(best.tolist()):
            scores = {
                label: round(float(probabilities[row_index, i].item()), 4)
                for i, label in enumerate(self.labels)
            }
            output.append({
                "label": self.labels[label_index],
                "confidence": float(probabilities[row_index, label_index].item()),
                "class_scores": scores,
            })
        return output


def _get_classifier():
    global _classifier, _load_error
    if _classifier is not None:
        return _classifier
    with _lock:
        if _classifier is None:
            try:
                _classifier = CTIBERTSemanticClassifier()
                _load_error = None
            except Exception as error:
                _load_error = str(error)
                raise
    return _classifier


def analyze_with_transformer(text):
    if not str(text or "").strip():
        return {
            "status": "error", "model_name": MODEL_NAME,
            "transformer_label": "Unavailable", "transformer_score": 0,
            "interpreted_intent": "No text was supplied for transformer analysis.",
            "class_scores": {}, "analyzed_at": datetime.now(timezone.utc).isoformat()
        }
    try:
        result = _get_classifier().predict_batch([str(text)])[0]
        label_text = result["label"].replace("_", " ").title()
        return {
            "status": "available", "model_name": MODEL_NAME,
            "transformer_label": result["label"],
            "transformer_score": round(result["confidence"], 4),
            "class_scores": result["class_scores"],
            "interpreted_intent": f"CTI-BERT found the strongest contextual similarity to {label_text} language.",
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as error:
        return {
            "status": "error", "model_name": MODEL_NAME,
            "transformer_label": "Unavailable", "transformer_score": 0,
            "class_scores": {}, "interpreted_intent": f"CTI-BERT could not run: {error}",
            "analyzed_at": datetime.now(timezone.utc).isoformat()
        }


def get_transformer_status():
    return {
        "status": "available" if _classifier is not None else ("error" if _load_error else "ready_to_load"),
        "model_name": MODEL_NAME,
        "message": _load_error or "CTI-BERT loads on the first transformer analysis request.",
        "device": str(_classifier.device) if _classifier is not None else "not loaded",
    }


def predict_batch(texts):
    return _get_classifier().predict_batch(texts)
