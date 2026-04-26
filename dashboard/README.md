# dashboard/ — static HTML/CSS/JS UI

Owns SRS module **M10 (HITL review dashboard)** plus the operator-facing pages
for live metrics, request logs, and configuration.

Per SRS UI design system:

- Background `#0A0C10`, cards `#1A1D24`.
- Primary blue `#3B82F6`, success `#10B981`, danger `#EF4444`, warning `#F59E0B`.
- Inter for text, Fira Code for code blocks.
- Charts via Chart.js or Plotly. No React/Vue/Angular.

Served as static files by Nginx in the compose stack.
