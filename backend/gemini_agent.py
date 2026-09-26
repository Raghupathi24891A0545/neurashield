"""NeuraShield Gemini AI Reasoning & Orchestration Layer.

Provides agentic reasoning for the NeuraShield Investigation Center:
- Interprets evidence collected by technical modules
- Recommends the next investigation capability or tool execution
- Correlates findings across URL, domain, webpage, email, and QR evidence
- Generates structured Threat DNA traits and executive threat assessments
- NEVER invents technical facts: relies strictly on verified evidence
- Backend-validated tool execution: AI cannot execute arbitrary network calls or code
- Full graceful degradation: if GEMINI_API_KEY is not configured or fails,
  deterministic decision logic proceeds transparently.
"""

import json
import os
import requests


# Supported Gemini models in order of preference
GEMINI_MODELS = [
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-1.5-pro",
]


class GeminiOrchestrator:
    """Agentic reasoning engine powered by Google Gemini API."""

    def __init__(self, api_key=None):
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "").strip()
        self._sdk_client = None
        self._sdk_available = False
        self._init_sdk()

    def _init_sdk(self):
        if not self.api_key:
            return
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._sdk_client = genai
            self._sdk_available = True
        except Exception:
            self._sdk_available = False

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def _call_rest_api(self, prompt: str, system_instruction: str = None, json_mode: bool = False) -> str:
        """Fallback REST caller for Gemini API if SDK is not present or throws."""
        for model in GEMINI_MODELS:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={self.api_key}"
            headers = {"Content-Type": "application/json"}
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                    "maxOutputTokens": 1024,
                }
            }
            if json_mode:
                payload["generationConfig"]["responseMimeType"] = "application/json"
            if system_instruction:
                payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=12)
                if resp.status_code == 200:
                    data = resp.json()
                    candidates = data.get("candidates", [])
                    if candidates:
                        parts = candidates[0].get("content", {}).get("parts", [])
                        if parts:
                            return parts[0].get("text", "")
            except Exception:
                continue
        return None

    def reason_next_action(self, current_evidence_summary: dict, available_tools: list) -> dict:
        """Ask Gemini to evaluate current evidence and recommend the next technical module.

        Returns:
            dict with 'recommended_tool', 'reasoning', 'priority', or None on fallback.
        """
        if not self.is_configured:
            return None

        system_prompt = (
            "You are the AI Reasoning Core of NeuraShield, an enterprise cybersecurity investigation platform. "
            "Your role is to orchestrate technical security analysis tools based strictly on collected evidence. "
            "NEVER fabricate technical data. Respond strictly in JSON format with keys: "
            "'recommended_tool' (one of the provided tool names or 'FINALIZE'), "
            "'reasoning' (concise 1-2 sentence explanation of why this step is needed), "
            "'missing_evidence' (list of 1-3 critical gaps you are trying to resolve)."
        )

        user_prompt = (
            f"Current Investigation State:\n"
            f"- Input Type: {current_evidence_summary.get('input_type')}\n"
            f"- Target: {current_evidence_summary.get('target')}\n"
            f"- Executed Modules: {', '.join(current_evidence_summary.get('executed_modules', []))}\n"
            f"- Known Domains: {', '.join(current_evidence_summary.get('domains', []))}\n"
            f"- Known URLs: {', '.join(current_evidence_summary.get('urls', []))}\n"
            f"- Key Evidence Collected: {json.dumps(current_evidence_summary.get('evidence_snippets', []), default=str)}\n\n"
            f"Available Unexecuted Tools:\n{json.dumps(available_tools, indent=2)}\n\n"
            f"Determine the single most appropriate next tool to run, or specify 'FINALIZE' if evidence is sufficient."
        )

        try:
            # Try SDK first if available
            raw_text = None
            if self._sdk_available and self._sdk_client:
                try:
                    model = self._sdk_client.GenerativeModel(
                        "gemini-1.5-flash",
                        system_instruction=system_prompt,
                        generation_config={"temperature": 0.2, "response_mime_type": "application/json"}
                    )
                    resp = model.generate_content(user_prompt)
                    raw_text = resp.text
                except Exception:
                    raw_text = None

            if not raw_text:
                raw_text = self._call_rest_api(user_prompt, system_instruction=system_prompt, json_mode=True)

            if raw_text:
                # Clean code fences if present
                clean = raw_text.strip()
                if clean.startswith("```json"):
                    clean = clean[7:]
                if clean.startswith("```"):
                    clean = clean[3:]
                if clean.endswith("```"):
                    clean = clean[:-3]
                parsed = json.loads(clean.strip())
                return {
                    "source": "Gemini-Reasoning-Core",
                    "status": "ACTIVE",
                    "recommended_tool": parsed.get("recommended_tool"),
                    "reasoning": parsed.get("reasoning", "Evidence-based decision from AI reasoning core."),
                    "missing_evidence": parsed.get("missing_evidence", [])
                }
        except Exception:
            pass

        return None

    def synthesize_threat_assessment(self, full_investigation_summary: dict) -> dict:
        """Synthesize executive assessment and Threat DNA interpretation from verified evidence."""
        if not self.is_configured:
            return None

        system_prompt = (
            "You are the NeuraShield Threat Intelligence Synthesis Core. "
            "Given verified technical evidence, produce an executive threat summary and Threat DNA profile. "
            "DO NOT hallucinate facts not present in the evidence. "
            "Respond strictly in JSON format with keys: "
            "'executive_summary' (concise executive summary paragraph), "
            "'threat_dna_identity' (1-3 words classifying attack archetype, e.g. 'Credential Harvester', 'Brand Impersonation', 'Benign Corporate Target'), "
            "'delivery_mechanism' (1 sentence summarizing delivery vector), "
            "'analyst_notes' (list of 2-3 key takeaways for SOC analysts)."
        )

        user_prompt = (
            f"Verified Investigation Data:\n"
            f"{json.dumps(full_investigation_summary, default=str, indent=2)}\n\n"
            f"Provide executive assessment and Threat DNA profile in JSON."
        )

        try:
            raw_text = None
            if self._sdk_available and self._sdk_client:
                try:
                    model = self._sdk_client.GenerativeModel(
                        "gemini-1.5-flash",
                        system_instruction=system_prompt,
                        generation_config={"temperature": 0.2, "response_mime_type": "application/json"}
                    )
                    resp = model.generate_content(user_prompt)
                    raw_text = resp.text
                except Exception:
                    raw_text = None

            if not raw_text:
                raw_text = self._call_rest_api(user_prompt, system_instruction=system_prompt, json_mode=True)

            if raw_text:
                clean = raw_text.strip()
                if clean.startswith("```json"):
                    clean = clean[7:]
                if clean.startswith("```"):
                    clean = clean[3:]
                if clean.endswith("```"):
                    clean = clean[:-3]
                parsed = json.loads(clean.strip())
                return {
                    "source": "Gemini-Synthesis-Core",
                    "executive_summary": parsed.get("executive_summary"),
                    "threat_dna_identity": parsed.get("threat_dna_identity"),
                    "delivery_mechanism": parsed.get("delivery_mechanism"),
                    "analyst_notes": parsed.get("analyst_notes", [])
                }
        except Exception:
            pass

        return None
