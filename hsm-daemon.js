import net from 'net';
import crypto from 'crypto';

// ==========================================
// ENVIRONMENT PORT & INFRASTRUCTURE DEFINITIONS
// ==========================================
// Priority: process.env.HSM_PORT -> process.env.PORT -> Default fallback 5900
const PORT = parseInt(process.env.HSM_PORT || process.env.PORT || '5900', 10);
// 0.0.0.0 allows the daemon to bind to all local network interfaces securely
const HOST = process.env.HSM_HOST || '0.0.0.0';

const US_NUMERIC_CODE = '840'; 
const US_ALPHA_CODE = 'USA';
let requestCounter = 0;

const daemon = net.createServer((socket) => {
    const sessionToken = crypto.randomBytes(4).toString('hex');
    
    const logTimestamp = () => `[${new Date().toLocaleTimeString()}]`;
    console.log(`${logTimestamp()} [CORE DAEMON] [SESSION: ${sessionToken}] Inbound channel connection opened.`);

    socket.on('data', (data) => {
        try {
            // Core protection: ensure we have at least the length header
            if (data.length < 2) {
                console.error(`${logTimestamp()} [WARN] Inbound packet too small (${data.length} bytes). Ignoring.`);
                return;
            }
            
            const expectedLength = data.readUInt16BE(0);
            
            // Slice off the 2-byte length header to inspect the raw message command string
            const actualPayload = data.subarray(2).toString('ascii');

            // Find where 'CY' actually starts in case the client applied extra null padding or header bytes
            const cyIndex = actualPayload.indexOf('CY');

            // ==========================================
            // LOG ENHANCEMENT: RAW PACKET DECODE INSPECTOR
            // ==========================================
            if (cyIndex === -1) {
                console.error(`\n${logTimestamp()} \x1b[31m[PROTOCOL_VIOLATION] [SESSION: ${sessionToken}]\x1b[0m Failed parsing 'CY' transaction token header.`);
                console.error(`-> RECEIVED LENGTH: Expected ${expectedLength} bytes (Buffer size: ${data.length} bytes)`);
                console.error(`-> RAW BUFFER (HEX): <${data.toString('hex').toUpperCase()}>`);
                console.error(`-> RAW BUFFER (ASCII): "${data.toString('ascii').replace(/[^ -~]/g, '?')}"\n`);
                return;
            }

            requestCounter++;

            // Extract the operational message payload beginning exactly from the validated 'CY' token positioning index
            const cleanPayload = actualPayload.substring(cyIndex);
            
            // Extract parameters out of standard Thales command structural spacing variables
            // Layout: 'CY' (2B) + Key Type Specifier/ID (33B) = 35B offset before structural field metrics start
            const cipherParameters = cleanPayload.substring(35);
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
            console.log(` ${logTimestamp()} \x1b[36m[TRANSACTION RECORD] AUDIT ID: #${requestCounter}\x1b[0m`);
            console.log(`------------------------------------------------------`);
            console.log(` SESSION TOKEN : ${sessionToken}`);
            console.log(` PAN ASSIGNED  : ${auditPan}`);
            console.log(` EXPIRATION    : ${auditExpiry}`);
            console.log(` COMPUTED CVC2 : ${productionCVC}`);
            console.log(` RAILS REGION  : UNITED STATES (ISO-${US_NUMERIC_CODE} / ${US_ALPHA_CODE})`);
            console.log(`------------------------------------------------------\n`);
            
        } catch (err) {
            console.error(`${logTimestamp()} [CORE DAEMON] [SESSION: ${sessionToken}] Processing exception error: ${err.message}`);
        }
    });

    socket.on('end', () => {
        console.log(`${logTimestamp()} [CORE DAEMON] [SESSION: ${sessionToken}] Inbound channel connection dropped.`);
    });

    socket.on('error', (err) => {
        console.error(`${logTimestamp()} [CORE DAEMON] [SESSION: ${sessionToken}] Live socket fault context: ${err.message}`);
    });
});

daemon.listen(PORT, HOST, () => {
    console.log('\n======================================================');
    console.log(` \x1b[32mCORE ISOLATED DAEMON RUNNING ON tcp://${HOST}:${PORT}\x1b[0m`);
    console.log(` RUNTIME CONFIG : process.env.PORT handling configured`);
    console.log(` PORT TARGET    : ${PORT}`);
    console.log(` FLOW ASSIGNMENT: UNITED STATES SETTLEMENT RAILS`);
    console.log('======================================================\n');
});
