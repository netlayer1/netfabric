# ── Stage 1: compile license_guard.py with Nuitka ────────────────────────────
FROM python:3.11-slim AS license-builder

WORKDIR /build

# Nuitka needs gcc + patchelf to produce a compiled extension module
RUN apt-get update && apt-get install -y \
    gcc \
    patchelf \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir nuitka

# Copy only the module we're compiling
COPY backend/license_guard.py .

# Compile to a .so extension module (not standalone — the rest of the app stays
# as plain Python and imports this compiled module at runtime).
RUN python -m nuitka \
    --module \
    --output-dir=/build/dist \
    --remove-output \
    license_guard.py

# The output is dist/license_guard.cpython-311-x86_64-linux-gnu.so (or similar)


# ── Stage 2: runtime image ────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# System deps for Netmiko/cryptography
RUN apt-get update && apt-get install -y \
    gcc \
    libffi-dev \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Replace the plain .py with the Nuitka-compiled .so
# Python's import system finds .so before .py, so no import changes needed.
COPY --from=license-builder /build/dist/license_guard*.so /app/backend/
RUN rm -f /app/backend/license_guard.py

# Create data and license mount point
RUN mkdir -p data/configs data/logs /app/license

# License file is injected at runtime via volume — not baked into the image.
# Fail fast if no license is present at startup.
VOLUME ["/app/license"]

EXPOSE 8000

CMD ["hypercorn", "backend.main:app", "--bind", "0.0.0.0:8000"]
