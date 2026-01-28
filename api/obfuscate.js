// api/obfuscate.js - Vercel Serverless Function
// This file handles obfuscation requests

const crypto = require('crypto');

class LuauObfuscator {
    constructor(options = {}) {
        this.options = {
            vmObfuscation: options.vmObfuscation !== false,
            stringEncryption: options.stringEncryption !== false,
            controlFlowFlattening: options.controlFlowFlattening !== false,
            variableRenaming: options.variableRenaming !== false,
            deadCodeInjection: options.deadCodeInjection !== false,
            antiTamper: options.antiTamper !== false,
            ...options
        };
        
        this.strings = [];
        this.stringMap = new Map();
        this.variables = new Map();
    }
    
    randomVar() {
        const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const prefix = '_' + chars[Math.floor(Math.random() * chars.length)];
        const suffix = Array.from({length: 8}, () => 
            chars[Math.floor(Math.random() * chars.length)]
        ).join('');
        return prefix + suffix;
    }
    
    encryptString(str) {
        const key = Math.floor(Math.random() * 255) + 1;
        const encrypted = [];
        
        for (let i = 0; i < str.length; i++) {
            encrypted.push(str.charCodeAt(i) ^ key);
        }
        
        return { encrypted, key };
    }
    
    obfuscateStrings(code) {
        if (!this.options.stringEncryption) return code;
        
        return code.replace(/"([^"\\]*(\\.[^"\\]*)*)"|'([^'\\]*(\\.[^'\\]*)*)'/g, (match) => {
            const str = match.slice(1, -1);
            
            if (!this.stringMap.has(str)) {
                const encrypted = this.encryptString(str);
                const index = this.strings.length;
                this.strings.push(encrypted);
                this.stringMap.set(str, index);
            }
            
            return `_decrypt(${this.stringMap.get(str)})`;
        });
    }
    
    generateStringDecryptor() {
        if (!this.options.stringEncryption || this.strings.length === 0) {
            return '';
        }
        
        const arrayData = this.strings.map(s => 
            `{${s.encrypted.join(',')},${s.key}}`
        ).join(',');
        
        return `
local _strings = {${arrayData}}
local _decrypt = function(i)
    local d = _strings[i + 1]
    local r = {}
    for j = 1, #d - 1 do
        r[j] = string.char(bit32.bxor(d[j], d[#d]))
    end
    return table.concat(r)
end
`;
    }
    
    obfuscateVariables(code) {
        if (!this.options.variableRenaming) return code;
        
        const keywords = new Set([
            'and', 'break', 'do', 'else', 'elseif', 'end', 'false', 'for', 
            'function', 'if', 'in', 'local', 'nil', 'not', 'or', 'repeat', 
            'return', 'then', 'true', 'until', 'while', 'game', 'print', 
            'tostring', 'tonumber', 'task', 'wait', 'spawn'
        ]);
        
        const localPattern = /local\s+([a-zA-Z_][a-zA-Z0-9_]*)/g;
        let match;
        
        while ((match = localPattern.exec(code)) !== null) {
            const varName = match[1];
            if (!keywords.has(varName) && !this.variables.has(varName)) {
                this.variables.set(varName, this.randomVar());
            }
        }
        
        for (const [original, obfuscated] of this.variables.entries()) {
            if (!keywords.has(original)) {
                const regex = new RegExp(`\\b${original}\\b`, 'g');
                code = code.replace(regex, obfuscated);
            }
        }
        
        return code;
    }
    
    injectDeadCode(code) {
        if (!this.options.deadCodeInjection) return code;
        
        const deadCode = [
            `local _dead1 = function() return ${Math.random()} * ${Math.random()} end`,
            `local _dead2 = "${this.randomVar()}"`,
            `local _dead3 = {${Array.from({length: 5}, () => Math.random()).join(',')}}`,
        ];
        
        return deadCode.join('\n') + '\n' + code;
    }
    
    vmObfuscate(code) {
        if (!this.options.vmObfuscation) return code;
        
        const vmTemplate = `
local _vm = {}
_vm.stack = {}
_vm.constants = {}
_vm.instructions = {}

function _vm:push(v) table.insert(self.stack, v) end
function _vm:pop() return table.remove(self.stack) end
function _vm:exec()
    local pc = 1
    while pc <= #self.instructions do
        local inst = self.instructions[pc]
        local op = inst[1]
        
        if op == "LOADK" then
            self:push(self.constants[inst[2]])
        elseif op == "ADD" then
            local b = self:pop()
            local a = self:pop()
            self:push(a + b)
        elseif op == "CALL" then
            local func = self:pop()
            local args = {}
            for i = 1, inst[2] do
                table.insert(args, 1, self:pop())
            end
            local result = func(table.unpack(args))
            if result then self:push(result) end
        elseif op == "RETURN" then
            return self:pop()
        end
        
        pc = pc + 1
    end
end
`;
        
        return vmTemplate + '\n-- Original code\n' + code;
    }
    
    addAntiTamper(code) {
        if (!this.options.antiTamper) return code;
        
        const antiTamper = `
-- Anti-tamper
local _check = function()
    local env = getfenv(0)
    if env.debug or env.getfenv ~= getfenv then
        while true do end
    end
end
task.spawn(_check)
`;
        
        return antiTamper + code;
    }
    
    obfuscate(code) {
        let obfuscated = code;
        
        if (this.options.stringEncryption) {
            obfuscated = this.obfuscateStrings(obfuscated);
        }
        
        if (this.options.variableRenaming) {
            obfuscated = this.obfuscateVariables(obfuscated);
        }
        
        if (this.options.deadCodeInjection) {
            obfuscated = this.injectDeadCode(obfuscated);
        }
        
        if (this.options.vmObfuscation) {
            obfuscated = this.vmObfuscate(obfuscated);
        }
        
        if (this.options.antiTamper) {
            obfuscated = this.addAntiTamper(obfuscated);
        }
        
        const decryptor = this.generateStringDecryptor();
        obfuscated = decryptor + obfuscated;
        
        return {
            code: obfuscated,
            stats: {
                originalSize: code.length,
                obfuscatedSize: obfuscated.length,
                sizeIncrease: Math.round(((obfuscated.length / code.length - 1) * 100) * 10) / 10,
                stringsEncrypted: this.strings.length,
                variablesRenamed: this.variables.size,
                linesAdded: obfuscated.split('\n').length - code.split('\n').length
            }
        };
    }
}

// Vercel Serverless Function Handler
module.exports = async (req, res) => {
    // CORS headers - allow all origins
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader(
        'Access-Control-Allow-Headers',
        'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version'
    );
    
    // Handle OPTIONS preflight
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    // Only accept POST
    if (req.method !== 'POST') {
        return res.status(405).json({ 
            error: 'Method not allowed',
            message: 'This endpoint only accepts POST requests'
        });
    }
    
    try {
        const { code, options } = req.body;
        
        // Validate input
        if (!code || typeof code !== 'string') {
            return res.status(400).json({ 
                error: 'Invalid input',
                message: 'Code must be a non-empty string'
            });
        }
        
        if (code.length > 100000) {
            return res.status(400).json({ 
                error: 'Code too large',
                message: 'Maximum code size is 100KB'
            });
        }
        
        // Generate unique session ID
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        // Obfuscate the code
        const obfuscator = new LuauObfuscator(options || {});
        const result = obfuscator.obfuscate(code);
        
        // Add session watermark
        const watermark = `-- Obfuscated by Kat Obfuscator | Session: ${sessionId.substring(0, 8)}\n`;
        
        // Return success response
        return res.status(200).json({
            success: true,
            sessionId: sessionId,
            obfuscated: watermark + result.code,
            stats: result.stats,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Obfuscation error:', error);
        return res.status(500).json({ 
            error: 'Obfuscation failed',
            message: error.message,
            details: process.env.NODE_ENV === 'development' ? error.stack : undefined
        });
    }
};
