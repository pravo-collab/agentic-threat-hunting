# 🚀 Hugging Face Deployment Guide

This guide will help you deploy the Agentic Threat Hunting & Incident Response System to Hugging Face Spaces.

## 📋 Prerequisites

1. **Hugging Face Account** - Sign up at [huggingface.co](https://huggingface.co/)
2. **OpenAI API Key** - Get from [platform.openai.com](https://platform.openai.com/)
3. **Pinecone API Key** (Optional) - Get from [pinecone.io](https://www.pinecone.io/)
4. **Git** - Installed on your system

## 🎯 Deployment Steps

### Step 1: Create a New Space

1. Go to [huggingface.co/spaces](https://huggingface.co/spaces)
2. Click **"Create new Space"**
3. Configure your Space:
   - **Space name**: `agentic-threat-hunting` (or your preferred name)
   - **License**: MIT
   - **SDK**: Streamlit
   - **Hardware**: CPU Basic (free) or upgrade for better performance
   - **Visibility**: Public or Private

### Step 2: Prepare Your Repository

```bash
# Navigate to your project directory
cd /Users/praveenradjassegarin/Documents/Interview_Prep/Artificial\ Intelligence/Praveen_Capstone1

# Rename README_HF.md to README.md for Hugging Face
cp README_HF.md README_HUGGINGFACE.md

# Create a .gitignore for sensitive files
cat > .gitignore << 'EOF'
.env
*.pyc
__pycache__/
.DS_Store
*.log
captures/*.pcap
captures/*.pcapng
models/*.h5
models/*.pkl
venv/
.venv/
EOF
```

### Step 3: Configure Secrets

In your Hugging Face Space settings, add these secrets:

1. Go to your Space → **Settings** → **Repository secrets**
2. Add the following secrets:

```
OPENAI_API_KEY=sk-...your-key...
PINECONE_API_KEY=pc-...your-key... (optional)
LANGCHAIN_API_KEY=lsv2_...your-key... (optional)
DEFAULT_MODEL=gpt-4o-mini
TEMPERATURE=0.1
```

### Step 4: Update Settings for Hugging Face

The following files are already configured for Hugging Face:

- ✅ `README_HF.md` - Hugging Face Space README with metadata
- ✅ `packages.txt` - System dependencies (libpcap-dev, tcpdump)
- ✅ `.streamlit/config.toml` - Streamlit configuration for port 7860
- ✅ `requirements.txt` - Python dependencies

### Step 5: Push to Hugging Face

```bash
# Add Hugging Face as a remote
git remote add hf https://huggingface.co/spaces/YOUR_USERNAME/agentic-threat-hunting

# Or if you prefer SSH
git remote add hf git@hf.co:spaces/YOUR_USERNAME/agentic-threat-hunting

# Copy README_HF.md as README.md for the Space
cp README_HF.md README.md

# Stage all files
git add .

# Commit
git commit -m "Initial Hugging Face deployment"

# Push to Hugging Face
git push hf main
```

### Step 6: Verify Deployment

1. Go to your Space URL: `https://huggingface.co/spaces/YOUR_USERNAME/agentic-threat-hunting`
2. Wait for the build to complete (5-10 minutes)
3. Check the **Logs** tab for any errors
4. Once built, the app will be available at the Space URL

## ⚙️ Configuration Notes

### Environment Variables

The app reads from Hugging Face Secrets automatically. Make sure these are set:

```python
# In src/config/settings.py
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
PINECONE_API_KEY = os.getenv("PINECONE_API_KEY", "")
LANGCHAIN_API_KEY = os.getenv("LANGCHAIN_API_KEY", "")
```

### Hardware Requirements

**Recommended Hardware:**
- **CPU Basic (Free)**: Works but slower
- **CPU Upgrade ($0.03/hour)**: Better performance
- **GPU T4 Small**: For faster ML inference (if using TensorFlow)

### File Size Limits

- **Repository**: 50 GB max
- **Individual files**: 10 GB max
- **PCAP uploads**: Limited by Streamlit's upload size (200 MB default)

## 🔧 Troubleshooting

### Build Fails

**Issue**: Dependencies fail to install

**Solution**:
```bash
# Check requirements.txt for version conflicts
# Ensure all packages are compatible
# Remove version pins if needed
```

### App Crashes on Startup

**Issue**: Missing environment variables

**Solution**:
- Verify all secrets are set in Space settings
- Check logs for specific error messages
- Ensure OPENAI_API_KEY is valid

### Zeek Not Available

**Issue**: Zeek installation fails

**Solution**:
- The app automatically falls back to Scapy
- Zeek is not available on Hugging Face Spaces
- This is expected behavior

### Pinecone Connection Issues

**Issue**: Can't connect to Pinecone

**Solution**:
- Verify PINECONE_API_KEY is set
- Check Pinecone dashboard for API key validity
- App works without Pinecone (limited features)

### Network Capture Disabled

**Issue**: Can't capture live network traffic

**Solution**:
- Network capture requires root privileges
- Not available in Hugging Face Spaces
- Use PCAP upload feature instead

## 🎨 Customization

### Update Space Metadata

Edit the header in `README.md`:

```yaml
---
title: Your Custom Title
emoji: 🛡️
colorFrom: red
colorTo: blue
sdk: streamlit
sdk_version: "1.28.0"
app_file: app.py
pinned: false
---
```

### Change Theme

Edit `.streamlit/config.toml`:

```toml
[theme]
primaryColor = "#YOUR_COLOR"
backgroundColor = "#YOUR_BG"
```

### Add Custom Domain

1. Go to Space Settings
2. Navigate to **Custom domain**
3. Follow instructions to set up your domain

## 📊 Monitoring

### View Logs

```bash
# In your Space, go to:
# Settings → Logs

# Or use the Hugging Face CLI
pip install huggingface_hub
huggingface-cli space logs YOUR_USERNAME/agentic-threat-hunting
```

### Check Usage

- Go to Space → **Settings** → **Usage**
- Monitor CPU/Memory usage
- Track API calls

## 🔄 Updates

### Push Updates

```bash
# Make changes locally
git add .
git commit -m "Update: description"

# Push to GitHub
git push origin main

# Push to Hugging Face
git push hf main
```

### Automatic Rebuilds

- Hugging Face automatically rebuilds on push
- Check build status in the Space interface
- Builds typically take 5-10 minutes

## 🚨 Important Notes

### Security

1. **Never commit API keys** to the repository
2. Use Hugging Face Secrets for sensitive data
3. Set Space to **Private** if handling sensitive data
4. Review logs regularly for security issues

### Performance

1. **Free tier limitations**:
   - CPU Basic: Slower performance
   - 16 GB storage
   - May sleep after inactivity

2. **Upgrade options**:
   - CPU Upgrade: Better performance
   - GPU: For ML inference
   - Persistent storage: For models

### Features Limitations on Hugging Face

❌ **Not Available:**
- Live network packet capture (requires root)
- Zeek installation (falls back to Scapy)
- Local file system writes (use temporary storage)

✅ **Available:**
- PCAP file upload and analysis
- AI-powered chat interface
- ML traffic classification
- RAG-based querying
- All agent workflows
- Report generation

## 📚 Additional Resources

- [Hugging Face Spaces Documentation](https://huggingface.co/docs/hub/spaces)
- [Streamlit on Spaces](https://huggingface.co/docs/hub/spaces-sdks-streamlit)
- [Managing Secrets](https://huggingface.co/docs/hub/spaces-overview#managing-secrets)

## 🆘 Support

If you encounter issues:

1. Check the [Hugging Face Community](https://discuss.huggingface.co/)
2. Review Space logs for errors
3. Open an issue on GitHub
4. Contact Hugging Face support

## ✅ Deployment Checklist

- [ ] Hugging Face account created
- [ ] Space created with Streamlit SDK
- [ ] OpenAI API key added to secrets
- [ ] Pinecone API key added (optional)
- [ ] Repository pushed to Hugging Face
- [ ] Build completed successfully
- [ ] App accessible via Space URL
- [ ] Tested PCAP upload
- [ ] Tested AI chat interface
- [ ] Verified ML classifier works
- [ ] Checked logs for errors

---

**Deployment Status**: Ready for Hugging Face Spaces 🚀

**Estimated Build Time**: 5-10 minutes

**Recommended Hardware**: CPU Upgrade or higher for best performance
