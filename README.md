# PCI Payment Page Script Check

Inventory the third-party scripts on your payment page, and fail the build when
one appears that you have not authorized.

PCI DSS v4.0.1 requirement **6.4.3** asks you to confirm every script loaded on
a payment page is authorized, assure its integrity, and keep an inventory with a
written justification. Requirement **11.6.1** asks you to detect unauthorized
change to those scripts and the security-impacting HTTP headers. Both became
mandatory on 31 March 2025.

The failure mode is rarely the payment provider's script. It is the analytics
tag added for a campaign, the chat widget added by support, and the tag manager
that lets either happen without a code review. This check runs in CI, so a
script that arrives without review fails a build instead of being discovered
during an assessment.

## Usage

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    url: https://yourstore.com/checkout
    allowed-domains: js.stripe.com, www.googletagmanager.com
    fail-on: high
```

Checking a page that is not deployed yet, or sits behind a login:

```yaml
- uses: ntoledo319/pci-payment-page-check@v1
  with:
    html-file: dist/checkout.html
    allowed-domains: js.stripe.com
```

### Inputs

| Input | Default | Description |
| --- | --- | --- |
| `url` | — | Public https URL of the payment page. Use this or `html-file`. |
| `html-file` | — | Saved HTML to check instead of a URL. |
| `allowed-domains` | — | Hosts you have authorized, comma-separated. Blank gives an inventory with no authorization check. |
| `fail-on` | `high` | Fail at this severity or above: `high`, `medium`, `low`, `never`. |
| `api-base` | hosted | Override the service endpoint. |

### Outputs

| Output | Description |
| --- | --- |
| `passed` | `true` when nothing met the `fail-on` threshold |
| `findings` | Number of findings returned |
| `report` | Full JSON result |

A table of findings is written to the job summary on every run.

## What it does and does not do

It reads the HTML your server returns and inspects the scripts it references.
It reports scripts served from hosts you did not list, scripts with no
integrity attribute, and inline blocks that need a justification in your
inventory.

It does **not** execute the page in a browser, so a script injected at runtime
by another script is outside what it can see. It cannot decide whether a script
is *authorized* — only you know that, which is why `allowed-domains` is yours to
supply. A clean result means the checks performed found nothing, not that
nothing is wrong.

It is software-generated evidence for qualified human review. It does not
determine your PCI DSS compliance, does not replace a Qualified Security
Assessor, and does not decide which self-assessment questionnaire applies to
you — your acquiring bank sets that.

## A correction worth knowing

Most write-ups still say SAQ A merchants must comply with 6.4.3 and 11.6.1.
That stopped being true on 31 March 2025: both were removed from SAQ A and
replaced with an eligibility criterion covering your **entire site**, not just
the payment page. Merchants who cannot meet that criterion validate to SAQ A-EP
or SAQ D, where both requirements still apply in full.

[What changed for SAQ A](https://qi.toledotechnologies.com/pci/saq-a-script-security-confirmation)
· [6.4.3 explained](https://qi.toledotechnologies.com/pci/pci-dss-6-4-3-payment-page-scripts)
· [11.6.1 explained](https://qi.toledotechnologies.com/pci/pci-dss-11-6-1-change-and-tamper-detection)

## Privacy

The action sends the page URL, or the HTML you point it at, and your authorized
domain list to the hosted check. No cardholder data is involved — the check
never sees any. Results are returned to the workflow and not retained against
an account, because no account exists.

Analysis runs as a hosted service rather than in your runner. Beyond keeping
the action dependency-free, the check has to fetch the contents of the scripts
a page references, and doing that from inside your CI network is something a
security tool should not do casually.

## Ongoing monitoring

Requirement 11.6.1 asks for evaluation at least every seven days, indefinitely
— a CI run only covers the moment you deploy. A hosted
[evidence ledger](https://qi.toledotechnologies.com/pci/pci-dss-11-6-1-change-and-tamper-detection)
re-checks the page on a schedule and records each evaluation in a hash-chained
history, so altered or deleted records are detectable.

## Licence

MIT. See `LICENSE`.
