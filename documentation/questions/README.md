# Defense / committee questions

Likely questions sorted by theme. Each has a prepared answer in 1-3
sentences plus a backing detail or file reference for when the panel
pushes for specifics.

**Read these the night before the viva.** Glance through one more
time the morning of. Don't memorise — internalise the shape of the
answer so you can paraphrase it under pressure.

## Files

| File | Theme | When this comes up |
|---|---|---|
| [01-architecture.md](01-architecture.md) | System design, containers, data flow, why-this-stack | Panel opens with "walk us through the architecture" |
| [02-machine-learning.md](02-machine-learning.md) | AE, HDBSCAN, consensus, training data, drift | When the ML-research panelist takes over |
| [03-rules-and-detection.md](03-rules-and-detection.md) | Coraza, CRS, mining, candidate rules, threat intel | When the security panelist takes over |
| [04-scope-and-limitations.md](04-scope-and-limitations.md) | What you didn't build and why, gap between SRS aspirations and shipped code | When someone asks "the SRS says X — where is it?" |
| [05-tricky.md](05-tricky.md) | Curveballs, gotcha questions, "what if I told you..." | When the panel tries to rattle you |

## Survival tips

- **It's fine to say "I haven't built that yet, here's why I chose
  not to."** The SDS / SRS are wide; the implementation is focused.
  This is a feature, not a bug — see `04-scope-and-limitations.md`.
- **If you don't know, say so.** "I don't know — let me think it
  through" is a better answer than a confident wrong one.
- **Anchor every answer in code you can show.** "It's in
  `ml/app/rulegen/orchestrator.py`" is stronger than "we wrote it
  somewhere."
- **Watch for compound questions.** "Why did you pick X *and* didn't
  you also do Y?" — answer each half separately so neither gets
  dropped.
