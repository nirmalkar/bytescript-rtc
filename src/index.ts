import './config';

import { createServer } from './server';

// Create and start the server
const { server } = createServer();
const port = Number(process.env.PORT || 4000);

server.listen(port, '0.0.0.0', () => {
  console.log(`🛰️  bytescript-rtc server running on http://localhost:${port}`);
  console.log(`Health check: http://localhost:${port}/health`);
});
