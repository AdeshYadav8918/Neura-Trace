import json
import os

try:
    import google.generativeai as genai
except ImportError:
    genai = None

try:
    from groq import Groq
except ImportError:
    Groq = None

def load_local_env():
    """Load local .env values when the assistant is used outside dashboard.py."""
    env_values = {}
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    try:
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as env_file:
                for line in env_file:
                    if "=" in line and not line.startswith("#"):
                        key, value = line.strip().split("=", 1)
                        env_values[key.strip()] = value.strip().strip("'\"")
    except Exception:
        pass
    return env_values

LOCAL_ENV = load_local_env()

class AIBrain:
    def __init__(self, gemini_api_key: str = "", groq_api_key: str = ""):
        self.gemini_api_key = (gemini_api_key or os.environ.get("GEMINI_API_KEY", "") or LOCAL_ENV.get("GEMINI_API_KEY", "")).strip()
        self.groq_api_key = (groq_api_key or os.environ.get("GROQ_API_KEY", "") or LOCAL_ENV.get("GROQ_API_KEY", "")).strip()
        self.model = None
        self.model_name = None
        self.active_provider = None
        self.groq_client = None
        preferred_order = os.environ.get("AI_PROVIDER_ORDER", "") or LOCAL_ENV.get("AI_PROVIDER_ORDER", "gemini,groq")
        self.provider_order = self._parse_provider_order(preferred_order)
        self.status_message = "AI backend not configured."
        preferred_gemini_model = (os.environ.get("GEMINI_MODEL", "") or LOCAL_ENV.get("GEMINI_MODEL", "")).strip()
        self.gemini_model_candidates = [
            name for name in [
                preferred_gemini_model,
                "gemini-flash-latest",
                "gemini-2.5-flash",
                "gemini-2.0-flash",
            ] if name
        ]
        preferred_groq_model = (os.environ.get("GROQ_MODEL", "") or LOCAL_ENV.get("GROQ_MODEL", "")).strip()
        self.groq_model_candidates = [
            name for name in [
                preferred_groq_model,
                "llama-3.3-70b-versatile",
                "openai/gpt-oss-20b",
                "llama-3.1-8b-instant",
            ] if name
        ]
        self.available_providers = []
        self.provider_issues = {}
        self.system_instruction = (
            "You are an expert military-grade cybersecurity analyst. "
            "You will receive raw network data, port scans, or packet captures. "
            "You MUST begin your response with either strictly '[SAFE]' or '[UNSAFE]'. "
            "If it is safe, briefly explain why. If it is unsafe, describe the vulnerabilities concisely."
        )
        self.assistant_instruction = (
            "You are NeuraTrace's AI assistant for network monitoring workflows. "
            "Use the provided scan, capture, and PCAP context to answer clearly. "
            "Prioritize concrete observations, likely causes, and next hardening steps."
        )

        self._initialize_gemini()
        self._initialize_groq()
        self._update_ready_status()

    def _parse_provider_order(self, provider_order: str):
        providers = [item.strip().lower() for item in provider_order.split(",") if item.strip()]
        normalized = []
        for provider in providers:
            if provider in {"gemini", "groq"} and provider not in normalized:
                normalized.append(provider)
        for provider in ["gemini", "groq"]:
            if provider not in normalized:
                normalized.append(provider)
        return normalized

    def _initialize_gemini(self):
        if genai is None:
            self.provider_issues["gemini"] = "google-generativeai is not installed."
            return
        if not self.gemini_api_key:
            self.provider_issues["gemini"] = "Missing GEMINI_API_KEY."
            return

        try:
            genai.configure(api_key=self.gemini_api_key)
            self.available_providers.append("gemini")
        except Exception as exc:
            self.provider_issues["gemini"] = f"Gemini unavailable: {exc}"

    def _initialize_groq(self):
        if Groq is None:
            self.provider_issues["groq"] = "groq is not installed."
            return
        if not self.groq_api_key:
            self.provider_issues["groq"] = "Missing GROQ_API_KEY."
            return

        try:
            self.groq_client = Groq(api_key=self.groq_api_key)
            self.available_providers.append("groq")
        except Exception as exc:
            self.provider_issues["groq"] = f"Groq unavailable: {exc}"

    def _update_ready_status(self):
        if self.available_providers:
            provider_labels = " + ".join(provider.title() for provider in self.available_providers)
            ordered_ready = [provider for provider in self.provider_order if provider in self.available_providers]
            primary = ordered_ready[0].title() if ordered_ready else self.available_providers[0].title()
            self.status_message = f"AI assistant ready ({provider_labels}; primary: {primary})."
        else:
            issues = [self.provider_issues.get(provider) for provider in self.provider_order if self.provider_issues.get(provider)]
            self.status_message = issues[0] if issues else "AI backend not configured."

    def is_available(self) -> bool:
        return bool(self.available_providers)

    def _offline_message(self, require_verdict: bool = True) -> str:
        if require_verdict:
            return f"[UNSAFE] {self.status_message}"
        return f"AI assistant unavailable. {self.status_message}"

    def _try_gemini(self, prompt: str) -> str:
        last_error = None
        for candidate in self.gemini_model_candidates:
            try:
                self.model = genai.GenerativeModel(candidate)
                self.model_name = candidate
                response = self.model.generate_content(prompt)
                self.active_provider = "gemini"
                self.status_message = f"AI assistant ready (Gemini: {self.model_name}; Groq fallback enabled)."
                return response.text
            except Exception as exc:
                last_error = exc
                error_text = str(exc).lower()
                if "not found" in error_text or "not supported" in error_text or "404" in error_text:
                    continue
                break
        raise RuntimeError(f"Gemini API Error ({self.model_name or 'unresolved model'}): {last_error}")

    def _try_groq(self, prompt: str) -> str:
        last_error = None
        for candidate in self.groq_model_candidates:
            try:
                completion = self.groq_client.chat.completions.create(
                    messages=[{"role": "user", "content": prompt}],
                    model=candidate,
                    temperature=0.2,
                )
                message = completion.choices[0].message.content or ""
                self.active_provider = "groq"
                self.model_name = candidate
                self.status_message = f"AI assistant ready (Groq: {self.model_name}; Gemini available)."
                return message
            except Exception as exc:
                last_error = exc
                error_text = str(exc).lower()
                if "not found" in error_text or "not supported" in error_text or "404" in error_text:
                    continue
                break
        raise RuntimeError(f"Groq API Error ({self.model_name or 'unresolved model'}): {last_error}")

    def _generate_response(self, prompt: str, require_verdict: bool = True) -> str:
        if not self.is_available():
            return self._offline_message(require_verdict=require_verdict)

        errors = []
        for provider in self.provider_order:
            if provider not in self.available_providers:
                continue
            try:
                if provider == "gemini":
                    return self._try_gemini(prompt)
                if provider == "groq":
                    return self._try_groq(prompt)
            except Exception as exc:
                errors.append(str(exc))

        self.status_message = "AI API Error: " + " | ".join(errors)
        if require_verdict:
            return f"[UNSAFE] {self.status_message}"
        return f"AI assistant unavailable. {self.status_message}"

    def _generate_strict_verdict(self, prompt: str) -> str:
        full_prompt = f"{self.system_instruction}\n\nDATA:\n{prompt}"
        return self._generate_response(full_prompt, require_verdict=True)

    def analyze_live_capture(self, stdout_log: str) -> str:
        return self._generate_strict_verdict(f"Review this raw capture log:\n{stdout_log}")

    def analyze_port_scan(self, port_data_str: str) -> str:
        return self._generate_strict_verdict(f"Review these mapped open ports:\n{port_data_str}")

    def analyze_device_security(self, scan_data_str: str, cve_list: list = None) -> str:
        prompt = f"Device Profile:\n{scan_data_str}\n"
        if cve_list:
            prompt += f"Known CVEs found:\n{json.dumps(cve_list)}\n"
        return self._generate_strict_verdict(prompt)

    def analyze_pcap_structure(self, pcap_summary_str: str) -> str:
        return self._generate_strict_verdict(f"Review this PCAP traffic structure map:\n{pcap_summary_str}")

    def ask_assistant(self, user_prompt: str, context: str = "") -> str:
        prompt_parts = [self.assistant_instruction]
        if context:
            prompt_parts.append(f"CURRENT CONTEXT:\n{context}")
        prompt_parts.append(f"USER REQUEST:\n{user_prompt}")
        return self._generate_response("\n\n".join(prompt_parts), require_verdict=False)
