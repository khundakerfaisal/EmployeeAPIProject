const fs = require('fs');
const path = require('path');

(async () => {
  try {
    const localtunnel = require('localtunnel');
    const port = Number(process.env.PORT) || 3000;
    const tunnel = await localtunnel({ port });

    const url = tunnel.url;
    const outPath = path.join(process.cwd(), 'tunnel-url.txt');
    fs.writeFileSync(outPath, url, { encoding: 'utf8' });
    console.log(`Public URL: ${url}`);

    tunnel.on('close', () => {
      // Tunnel closed
    });
  } catch (err) {
    console.error('Failed to start tunnel:', err.message);
    process.exit(1);
  }
})();


