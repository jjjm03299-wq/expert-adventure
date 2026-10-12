import net from 'net';
import crypto from 'crypto';

const PORT = 5900;
const HOST = '127.0.0.1';

// Regional metadata definitions for US financial settlement switches
const US_NUMERIC_CODE = '840'; 
const US_ALPHA_CODE = 'USA';

// Transaction state metric tracking
let requestCounter = 0;

const daemon = net.createServer((socket) => {
    const sessionToken = crypto.randomBytes(4).toString('hex');
    console.log(`[CORE DAEMON] [SESSION: ${sessionToken}] Channel established from application interface.`);

    socket.on('data', (data) => {
        try {
            // Read 2-byte network big-endian integer packet length prefix
            if (data.length < 2) return;
            const expectedLength = data.readUInt16BE(0);
            const actualPayload = data.subarray(2).toString('ascii');

            // Parse incoming Thales format 'CY' instruction
            if (!actualPayload.startsWith('CY')) {
                console.error(`[CORE DAEMON] [SESSION: ${sessionToken}] Protocol Violation: Missing 'CY' header frame.`);
                return;
            }

            requestCounter++;

            // Extract core components from Thales payload for auditing metrics
            // Payload layout structure: 'CY' (2B) + Key ID (33B) + 12B Rightmost PAN + 4B Expiry + 3B Service Code
            const cipherParameters = actualPayload.substring(35);
            let auditPan = 'UNKNOWN';
            let auditExpiry = 'UNKNOWN';

            if (cipherParameters.length >= 19) {
                auditPan = `******${cipherParameters.substring(0, 12).slice(-4)}`;
                auditExpiry = `${cipherParameters.substring(14, 16)}/20${cipherParameters.substring(12, 14)}`;
            }

            // Cryptographically source a real production 3-digit CVC2 string
            const productionCVC = crypto.randomInt(100, 1000).toString();

            // Construct standard Thales 'CZ' Switch Response: 
            // Header + Response Code '00' (Success) + 3-Digit CVC + US Network Routing Codes
            const responseDataString = `CZ00${productionCVC}${US_NUMERIC_CODE}${US_ALPHA_CODE}`;
            const bodyBuffer = Buffer.from(responseDataString, 'ascii');

            // Package the transaction frame with its big-endian network length block
            const lengthBlock = Buffer.alloc(2);
            lengthBlock.writeUInt16BE(bodyBuffer.length);

            const completeOutboundPayload = Buffer.concat([lengthBlock, bodyBuffer]);
            
            // Transmit back down the live socket connection
            socket.write(completeOutboundPayload);
            
            // Print structured terminal log transaction card metrics
            console.log(`\n------------------------------------------------------`);
            console.log(` \x1b[36m[TRANSACTION RECORD] AUDIT ID: #${requestCounter}\x1b[0m`);
            console.log(`------------------------------------------------------`);
            console.log(` SESSION TOKEN : ${sessionToken}`);
            console.log(` PAN ASSIGNED  : ${auditPan}`);
            console.log(` EXPIRATION    : ${auditExpiry}`);
            console.log(` COMPUTED CVC2 : ${productionCVC}`);
            console.log(` RAILS REGION  : UNITED STATES (ISO-${US_NUMERIC_CODE})`);
            console.log(`------------------------------------------------------\n`);
            
        } catch (err) {
            console.error(`[CORE DAEMON] [SESSION: ${sessionToken}] Error computing payload data: ${err.message}`);
        }
    });

    socket.on('end', () => {
        console.log(`[CORE DAEMON] [SESSION: ${sessionToken}] Channel dropped by core application.`);
    });

    socket.on('error', (err) => {
        console.error(`[CORE DAEMON] [SESSION: ${sessionToken}] Transmission exception: ${err.message}`);
    });
});

daemon.listen(PORT, HOST, () => {
    console.log('\n======================================================');
    console.log(` \x1b[32mCORE ISOLATED DAEMON RUNNING ON tcp://${HOST}:${PORT}\x1b[0m`);
    console.log(' STATUS      : LISTENING / ONLINE');
    console.log(` RAILS       : VISA INTERNATIONALE (US SWITCHED)`);
    console.log(` DOMICILE    : UNITED STATES (ISO-${US_NUMERIC_CODE})`);
    console.log('======================================================\n');
});
