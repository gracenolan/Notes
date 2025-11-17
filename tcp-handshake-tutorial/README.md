# TCP Handshake Tutorial for Security Engineers

An interactive, browser-based tutorial designed to teach security engineers the fundamentals of TCP handshakes, including security implications, attack vectors, and practical analysis techniques.

## Features

- **Interactive Visualizations**: Animated TCP three-way handshake with packet flow
- **Step-by-Step Learning**: 6 comprehensive lessons covering all aspects of TCP handshakes
- **Practical Security Focus**: Real-world attack scenarios (SYN floods, port scanning, session hijacking)
- **Hands-On Exercises**: Interactive quiz to test understanding
- **Tool References**: Examples using Wireshark, tcpdump, nmap, scapy, and more
- **Fully Self-Contained**: Single HTML file, no external dependencies
- **Mobile Responsive**: Works on desktop, tablet, and mobile devices

## Tutorial Contents

### Lesson 1: Introduction to TCP
- Why TCP matters for security engineers
- TCP vs UDP comparison
- Key concepts: sequence numbers, acknowledgments, flags, ports

### Lesson 2: The Three-Way Handshake
- Interactive animation of SYN → SYN-ACK → ACK
- Detailed packet analysis with headers
- Sequence and acknowledgment number calculator
- Step-by-step and continuous animation modes

### Lesson 3: Security Implications
- SYN flood attacks and defenses
- Port scanning techniques (SYN, Connect, FIN, XMAS, NULL scans)
- TCP session hijacking
- Firewall evasion techniques

### Lesson 4: Connection Termination
- Four-way handshake (FIN packets)
- RST (Reset) packets and their security implications
- TCP state diagram

### Lesson 5: Practical Exercises
- 5 interactive quiz questions
- Handshake identification
- Attack pattern recognition
- Sequence number calculations

### Lesson 6: Real-World Tools
- Wireshark filters for TCP analysis
- tcpdump command examples
- nmap port scanning
- Scapy packet crafting
- netstat/ss connection monitoring

## Local Testing

### Option 1: Python HTTP Server
```bash
cd tcp-handshake-tutorial
python3 -m http.server 8000
```
Then open http://localhost:8000 in your browser.

### Option 2: Open Directly
Simply open `index.html` in any modern web browser (Chrome, Firefox, Safari, Edge).

## Deployment to AWS S3

### Prerequisites
- AWS account
- AWS CLI installed and configured
- Appropriate IAM permissions for S3

### Step 1: Create S3 Bucket
```bash
# Replace 'your-bucket-name' with a unique bucket name
aws s3 mb s3://your-bucket-name --region us-east-1
```

### Step 2: Enable Static Website Hosting
```bash
aws s3 website s3://your-bucket-name \
  --index-document index.html \
  --error-document index.html
```

### Step 3: Configure Bucket Policy for Public Access
Create a file named `bucket-policy.json`:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicReadGetObject",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::your-bucket-name/*"
    }
  ]
}
```

Apply the policy:
```bash
aws s3api put-bucket-policy \
  --bucket your-bucket-name \
  --policy file://bucket-policy.json
```

### Step 4: Upload Files
```bash
aws s3 sync . s3://your-bucket-name \
  --exclude ".git/*" \
  --exclude "README.md" \
  --exclude "bucket-policy.json" \
  --cache-control "max-age=3600"
```

### Step 5: Access Your Tutorial
Your tutorial will be available at:
```
http://your-bucket-name.s3-website-us-east-1.amazonaws.com
```

### Optional: Configure CloudFront CDN
For better performance and HTTPS support:

```bash
# Create CloudFront distribution (requires additional configuration)
aws cloudfront create-distribution \
  --origin-domain-name your-bucket-name.s3-website-us-east-1.amazonaws.com \
  --default-root-object index.html
```

## Alternative Deployment Options

### GitHub Pages
1. Create a GitHub repository
2. Upload the `index.html` file
3. Go to Settings → Pages
4. Select branch and root folder
5. Your tutorial will be available at: `https://username.github.io/repo-name/`

### Netlify (Easy Drag-and-Drop)
1. Go to https://app.netlify.com/drop
2. Drag the `tcp-handshake-tutorial` folder
3. Instant deployment with HTTPS

### Vercel
```bash
npm i -g vercel
cd tcp-handshake-tutorial
vercel --prod
```

### Simple HTTP Server (For Internal Use)
```bash
# Using Python
python3 -m http.server 8080

# Using Node.js (if http-server is installed)
npx http-server -p 8080

# Using PHP
php -S localhost:8080
```

## Cost Estimates

### AWS S3 Hosting
- **Storage**: $0.023 per GB/month (tutorial is < 100KB)
- **Data Transfer**: First 1GB free, then $0.09 per GB
- **Requests**: $0.0004 per 1,000 GET requests
- **Estimated monthly cost**: < $1 for moderate traffic

### CloudFront (Optional)
- **Data Transfer**: First 1TB free for 12 months, then $0.085 per GB
- **Requests**: First 10M free for 12 months, then $0.0075 per 10,000 requests

### Free Alternatives
- GitHub Pages: Free for public repositories
- Netlify: 100GB bandwidth/month free
- Vercel: 100GB bandwidth/month free

## Security Considerations

### Content Security
- The tutorial is entirely static (HTML/CSS/JS)
- No server-side processing required
- No database or user data collection
- No external dependencies or CDN links

### Access Control
For internal/private deployment:
- Use S3 bucket policies to restrict by IP range
- Require authentication via CloudFront signed URLs
- Deploy behind VPN or corporate network

### HTTPS
- Use CloudFront for HTTPS on S3
- GitHub Pages, Netlify, and Vercel provide HTTPS by default

## Customization

The tutorial is contained in a single HTML file for easy customization:

- **Styling**: Modify the `<style>` section
- **Content**: Edit lesson text directly in HTML
- **Animations**: Adjust JavaScript timing and behavior
- **Branding**: Add your organization's logo and colors

## Browser Compatibility

Tested and working on:
- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## License

This tutorial is provided for educational purposes. Feel free to use, modify, and distribute for security training.

## Contributing

Suggestions for improvements:
- Additional attack scenarios
- More interactive exercises
- Packet capture examples (PCAP files)
- Video demonstrations
- Integration with online labs

## Support

For questions or issues:
1. Review the tutorial content
2. Check browser console for JavaScript errors
3. Ensure JavaScript is enabled
4. Try a different modern browser

## Credits

Created for security engineering education with focus on:
- Network protocol analysis
- Attack pattern recognition
- Defensive security measures
- Hands-on learning

---

**Start learning now**: Open `index.html` in your browser!
