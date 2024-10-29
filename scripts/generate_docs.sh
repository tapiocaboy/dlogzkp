#!/bin/bash

# Exit on any error
set -e

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}Generating Rust documentation...${NC}"

# Create docs directory if it doesn't exist
mkdir -p docs

# Clean previous docs
if [ -d "docs" ]; then
    echo "Cleaning previous documentation..."
    rm -rf docs/*
fi

# Generate documentation with all features enabled
echo "Building documentation..."
cargo doc --no-deps --document-private-items --all-features

# Move the generated docs to the docs directory
echo "Moving documentation to docs directory..."
cp -r target/doc/* docs/

# Create an index.html file that redirects to the main documentation
cat > docs/index.html << EOF
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Schnorr ZK DLOG Proof Documentation</title>
    <meta http-equiv="refresh" content="0; url=schnorr_zk_dlog/index.html">
    <style>
      body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        margin: 0;
        padding: 20px;
        background-color: #f5f5f5;
      }
      .container {
        max-width: 800px;
        margin: 0 auto;
        background-color: white;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
      }
      h1 {
        color: #333;
        margin-top: 0;
      }
      a {
        color: #0366d6;
        text-decoration: none;
      }
      a:hover {
        text-decoration: underline;
      }
    </style>
  </head>
  <body>
    <div class="container">
      <h1>Schnorr ZK DLOG Proof Documentation</h1>
      <p>Redirecting to <a href="schnorr_zk_dlog/index.html">documentation</a>...</p>
    </div>
  </body>
</html>
EOF

# Add .nojekyll file for GitHub Pages
touch docs/.nojekyll

echo -e "${GREEN}Documentation generated successfully!${NC}"
echo -e "You can view the documentation by opening ${GREEN}docs/index.html${NC} in your browser"

# Check if git is available and if we're in a git repository
if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    echo -e "\n${GREEN}Adding documentation to git...${NC}"
    git add docs
    echo -e "You can now commit the changes with: ${GREEN}git commit -m \"Update documentation\"${NC}"
else
    echo -e "\n${RED}Not a git repository or git not found. Skipping git operations.${NC}"
fi 