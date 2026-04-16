"""
LLM client for agentic forensic investigation.

Uses Ollama's /api/chat endpoint with tool calling support.
Falls back gracefully if Ollama is unavailable.
"""

import json
import urllib.request
import urllib.error


class OllamaClient:
    def __init__(self, model="llama3.1", base_url="http://localhost:11434"):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._available = None

    def is_available(self):
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(
                f"{self.base_url}/api/tags",
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                self._available = resp.status == 200
        except Exception:
            self._available = False
        return self._available

    def chat(self, messages, tools=None, temperature=0.2):
        """
        Send a chat request to Ollama.

        Args:
            messages: List of {"role": "...", "content": "..."} dicts
            tools: Optional list of tool definitions for tool calling
            temperature: Sampling temperature

        Returns:
            dict with keys:
                - "content": str (text response)
                - "tool_calls": list of tool call dicts (if any)
                - "raw": full response dict
        """
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        if tools:
            payload["tools"] = tools

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/chat",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=120) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            return {
                "content": f"[LLM unavailable: {e}]",
                "tool_calls": [],
                "raw": {},
            }
        except Exception as e:
            return {
                "content": f"[LLM error: {e}]",
                "tool_calls": [],
                "raw": {},
            }

        message = body.get("message", {})
        content = message.get("content", "")
        tool_calls = message.get("tool_calls", [])

        return {
            "content": content,
            "tool_calls": tool_calls,
            "raw": body,
        }

    def chat_with_tools(self, messages, tools, tool_executor, max_rounds=5):
        """
        Run a multi-turn tool-calling loop.

        The LLM calls tools, we execute them, feed results back,
        and repeat until the LLM stops calling tools or we hit max_rounds.

        Args:
            messages: Initial message list
            tools: Tool definitions
            tool_executor: callable(tool_name, tool_args) -> str
            max_rounds: Maximum tool-calling rounds

        Returns:
            tuple: (final_content: str, conversation: list, tool_trace: list)
        """
        conversation = list(messages)
        tool_trace = []

        for round_num in range(max_rounds):
            response = self.chat(conversation, tools=tools)

            content = response.get("content", "")
            tool_calls = response.get("tool_calls", [])

            # Add assistant message to conversation
            assistant_msg = {"role": "assistant", "content": content}
            if tool_calls:
                assistant_msg["tool_calls"] = tool_calls
            conversation.append(assistant_msg)

            if not tool_calls:
                # LLM is done — return final response
                return content, conversation, tool_trace

            # Execute each tool call
            for tc in tool_calls:
                func = tc.get("function", {})
                tool_name = func.get("name", "unknown")
                tool_args = func.get("arguments", {})

                # Execute the tool
                try:
                    result = tool_executor(tool_name, tool_args)
                except Exception as e:
                    result = f"Tool execution error: {e}"

                tool_trace.append({
                    "round": round_num,
                    "tool": tool_name,
                    "args": tool_args,
                    "result_preview": str(result)[:500],
                })

                # Feed tool result back to LLM
                conversation.append({
                    "role": "tool",
                    "content": str(result),
                })

        # Max rounds reached — get final summary
        conversation.append({
            "role": "user",
            "content": "You have reached the maximum number of investigation rounds. "
                       "Please synthesize your findings now based on all the evidence gathered so far.",
        })
        response = self.chat(conversation)
        final_content = response.get("content", "")
        conversation.append({"role": "assistant", "content": final_content})

        return final_content, conversation, tool_trace
