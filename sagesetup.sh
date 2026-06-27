#!/usr/bin/env bash
set -euo pipefail

# Ensure submodules are present
if [ ! -d "deps/SageLang" ] || [ ! -d "deps/SageVM" ]; then
  echo "Initializing SageLang and SageVM submodules..."
  git submodule add https://github.com/Night-Traders-Dev/SageLang deps/SageLang
  git submodule add https://github.com/Night-Traders-Dev/SageVM deps/SageVM
fi

cd deps/SageLang
./sagesync
./sagemake --make-only

cd ../SageVM
git submodule update --init
rm -rf .deps SageLang
cp -R ../SageLang .deps/SageLang
./sagemake build

echo "SageLang and SageVM built successfully."
