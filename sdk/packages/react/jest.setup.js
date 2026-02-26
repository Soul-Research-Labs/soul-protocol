// Polyfill TextEncoder/TextDecoder for jsdom environment (needed by viem)
const { TextEncoder, TextDecoder } = require("util");
global.TextEncoder = TextEncoder;
global.TextDecoder = TextDecoder;
