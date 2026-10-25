"""Official OpenAI and Anthropic SDKs against the test gateway (TestServeForSDK): a block must surface as the SDK's
typed PermissionDeniedError carrying the decision id, a clean call must parse normally, and a stream the gateway
stops must end the way a filtered stream ends."""
import sys
import anthropic
import openai

gw, key = sys.argv[1], "gw-key-chat-0123456789"
secret = "deploy with aws_access_key_id=AKIAIOSFODNN7EXAMPLE and aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

oa = openai.OpenAI(base_url=gw + "/openai/v1", api_key=key, max_retries=0)
try:
    oa.chat.completions.create(model="m", messages=[{"role": "user", "content": secret}])
    sys.exit("openai: block not raised")
except openai.PermissionDeniedError as e:
    print("openai block ->", type(e).__name__, e.status_code, e.response.headers["x-wantimpres26-decision-id"], e.body["code"])
r = oa.chat.completions.create(model="m", messages=[{"role": "user", "content": "opening hours?"}])
print("openai clean ->", type(r).__name__, r.choices[0].message.content[:30])
try:
    list(oa.responses.create(model="m", input="hi", stream=True))
    sys.exit("openai: responses stream refusal not raised")
except openai.BadRequestError as e:
    print("openai responses stream ->", type(e).__name__, e.status_code)

an = anthropic.Anthropic(base_url=gw + "/anthropic", api_key=key, max_retries=0)
try:
    an.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": secret}])
    sys.exit("anthropic: block not raised")
except anthropic.PermissionDeniedError as e:
    print("anthropic block ->", type(e).__name__, e.status_code, e.response.headers["x-wantimpres26-decision-id"], e.body["error"]["type"])
m = an.messages.create(model="m", max_tokens=10, messages=[{"role": "user", "content": "AML red flags?"}])
print("anthropic clean ->", type(m).__name__, m.content[0].text[:30])

# Streams stopped mid-way by the gateway (canary leak): a normal, filtered end for each SDK.
ck = "gw-key-canary-0123456789"
oc = openai.OpenAI(base_url=gw + "/vllm/v1", api_key=ck, max_retries=0)
chunks = list(oc.chat.completions.create(model="m", stream=True, messages=[
    {"role": "system", "content": "You are the branch assistant."}, {"role": "user", "content": "Opening hours?"}]))
text = "".join(c.choices[0].delta.content or "" for c in chunks if c.choices)
fin = [c.choices[0].finish_reason for c in chunks if c.choices and c.choices[0].finish_reason]
assert fin == ["content_filter"] and "[WANTIMPRES-26: response stopped" in text and "WTP26-" not in text, (fin, text[-300:])
print("openai stream block ->", fin[0], text.strip().splitlines()[-1][:70])

ac = anthropic.Anthropic(base_url=gw + "/anthropic", api_key=ck, max_retries=0)
with ac.messages.stream(model="m", max_tokens=100, system="You are the branch assistant.",
                        messages=[{"role": "user", "content": "Opening hours?"}]) as st:
    text = "".join(st.text_stream)
    final = st.get_final_message()
assert final.stop_reason == "refusal" and "[WANTIMPRES-26: response stopped" in text and "WTP26-" not in text, (final.stop_reason, text[-300:])
print("anthropic stream block ->", final.stop_reason, len(final.content), "blocks,", text.strip().splitlines()[-1][:70])
