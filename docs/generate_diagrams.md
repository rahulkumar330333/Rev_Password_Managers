## Generate Mermaid diagrams as images

This project keeps Mermaid sources in Markdown (`docs/ER_Diagram.md`, `docs/Project_Flow.md`). If your Git host does not render Mermaid, generate SVG/PNG files locally or in CI using one of these methods.

Option A — using npx (Node.js required):

```bash
# Install and run mermaid-cli to generate SVG
npx -y @mermaid-js/mermaid-cli -i docs/ER_Diagram.md -o docs/images/ER_Diagram.svg
npx -y @mermaid-js/mermaid-cli -i docs/Project_Flow.md -o docs/images/Project_Flow.svg
```

If `mermaid-cli` cannot read a full markdown file, extract the mermaid code block into a `.mmd` file and run:

```bash
npx -y @mermaid-js/mermaid-cli -i docs/er_diagram.mmd -o docs/images/ER_Diagram.svg
```

Option B — Docker (no Node install):

```bash
# create er_diagram.mmd containing the mermaid block
docker run --rm -v "$PWD":/data minlag/mermaid-cli -i /data/docs/er_diagram.mmd -o /data/docs/images/ER_Diagram.svg
```

Option C — GitHub Actions CI (recommended for automated rendering): include a job that runs `npx @mermaid-js/mermaid-cli` and commits the generated images back to the repo.

Notes:
- The repo includes placeholder SVGs at `docs/images/ER_Diagram.svg` and `docs/images/Project_Flow.svg` so GitHub shows an image even if Mermaid rendering is disabled. Replace them by generating proper images and committing the results.
