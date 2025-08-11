const fs = require("fs-extra");
const path = require('path');
const { exec, spawn } = require("child_process");

// Enhanced configuration with additional stability options
const defaultConfigContent = {
  "version": "1.0.2",
  "language": "en",
  "email": "",
  "password": "",
  "useEnvForCredentials": false,
  "envGuide": "When useEnvForCredentials enabled, it will use the process.env key provided for email and password",
  "DeveloperMode": true,
  "autoCreateDB": true,
  "allowInbox": false,
  "autoClean": true,
  "adminOnly": false,
  "encryptSt": false,
  "removeSt": false,
  "UPDATE": {
    "Package": false,
    "EXCLUDED": ["chalk", "mqtt", "https-proxy-agent"],
    "Info": "Automatic package updates configuration"
  },
  "commandDisabled": [],
  "eventDisabled": [],
  "BOTNAME": "Fmate💘",
  "PREFIX": "?",
  "ADMINBOT": ["61555393416824"],
  "DESIGN": {
    "Title": "BOT CONSOLE",
    "Theme": "Blue",
    "Admin": "Hassan"
  },
  "APPSTATEPATH": "appstate.json",
  "DEL_FUNCTION": false,
  "ADD_FUNCTION": true,
  // Enhanced FCA options with additional stability parameters
  "FCAOption": {
    "forceLogin": false,
    "listenEvents": true,
    "autoMarkDelivery": true,
    "autoMarkRead": false,
    "logLevel": "silent",
    "selfListen": false,
    "online": true,
    "userAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "autoReconnect": true,
    "autoRestore": true,
    "syncUp": true,
    "delay": 500,
    "maxRetries": 5,
    "retryDelay": 30000,
    "enableCookies": true,
    "browserArgs": [
      "--disable-notifications",
      "--disable-infobars",
      "--disable-web-security",
      "--disable-features=IsolateOrigins,site-per-process",
      "--disable-blink-features=AutomationControlled"
    ]
  },
  "daily": { "cooldownTime": 43200000, "rewardCoin": 500 },
  "work": { "cooldownTime": 1200000 },
  "help": { "autoUnsend": true, "delayUnsend": 60 },
  "adminUpdate": { "autoUnsend": true, "sendNoti": true, "timeToUnsend": 10 },
  "adminNoti": { "autoUnsend": true, "sendNoti": true, "timeToUnsend": 10 },
  "humanLikeDelay": { "min": 2000, "max": 8000 },
  "randomActivity": { 
    "status": true, 
    "intervalMin": 60, 
    "intervalMax": 180,
    "activities": ["markRead", "goOffline", "scrollFeed"]
  },
  "autoRestart": {
    "enabled": true,
    "schedule": "0 */6 * * *",
    "notifyAdmins": true
  },
  "heartbeat": {
    "enabled": true,
    "interval": 300000,
    "timeout": 60000,
    "maxFailures": 3
  },
  "unsendEmojis": ["🤓", "🚫"],
  "security": {
    "enableProxy": false,
    "proxyList": [],
    "rotateUserAgent": true,
    "enableCookiePersistence": true,
    "enableRandomDelays": true
  }
};

// Enhanced cookie domain fixing function
function fixCookieDomains(appState) {
    return appState.map(cookie => {
        const newCookie = {...cookie};
        
        if (['c_user', 'xs', 'fr', 'datr'].includes(newCookie.name)) {
            newCookie.domain = '.facebook.com';
            newCookie.sameSite = 'none';
            
            if (newCookie.name === 'c_user' || newCookie.name === 'xs') {
                const messengerCookie = {...newCookie};
                messengerCookie.domain = '.messenger.com';
                return [newCookie, messengerCookie];
            }
            return newCookie;
        }
        
        newCookie.sameSite = 'none';
        return newCookie;
    }).flat();
}

// Enhanced login function with retry logic
async function performLogin(loginData, fcaLoginOptions) {
    if (loginData.appState) {
        loginData.appState = fixCookieDomains(loginData.appState);
    }
    
    return new Promise((resolve, reject) => {
        login(loginData, fcaLoginOptions, (err, api) => {
            if (err) {
                return reject(err);
            }
            resolve(api);
        });
    });
}

// Enhanced chalk implementation
let chalk;
try {
  chalk = require('chalk');
} catch (e) {
  chalk = {
    red: (text) => `\x1b[31m${text}\x1b[0m`,
    green: (text) => `\x1b[32m${text}\x1b[0m`,
    blue: (text) => `\x1b[34m${text}\x1b[0m`,
    yellow: (text) => `\x1b[33m${text}\x1b[0m`,
    blueBright: (text) => `\x1b[94m${text}\x1b[0m`,
    magenta: (text) => `\x1b[35m${text}\x1b[0m`,
    cyan: (text) => `\x1b[36m${text}\x1b[0m`,
    hex: (color) => (text) => {
      const hex = color.replace('#', '');
      const r = parseInt(hex.substring(0, 2), 16);
      const g = parseInt(hex.substring(2, 4), 16);
      const b = parseInt(hex.substring(4, 6), 16);
      return `\x1b[38;2;${r};${g};${b}m${text}\x1b[0m`;
    }
  };
  console.warn(chalk.yellow("Using fallback chalk implementation. For full features, run: npm install chalk@4.1.2"));
}

const check = require("get-latest-version");
const semver = require("semver");
const { readdirSync, readFileSync, writeFileSync } = require("fs-extra");
const { join, resolve } = require("path");
const express = require("express");
const moment = require("moment-timezone");
const cron = require("node-cron");
const axios = require('axios');
const login = require('hassan-fca');
const puppeteer = require('puppeteer-extra');
const StealthPlugin = require('puppeteer-extra-plugin-stealth');

puppeteer.use(StealthPlugin());

// Enhanced utility functions
global.utils = {
  findUid: async function(url) {
    if (!url) throw new Error("URL is required");
    
    try {
      if (!url.startsWith("http")) url = "https://" + url;
      
      const fbRegex = /(?:https?:\/\/)?(?:www\.|m\.)?(facebook|fb)\.(com|me)\/(?:profile\.php\?id=(\d+)|([a-zA-Z0-9.\-_]+))/;
      const match = url.match(fbRegex);
      
      if (!match) throw new Error("Invalid Facebook URL format");
      
      const usernameOrId = match[3] || match[4];
      if (!usernameOrId) throw new Error("Could not extract ID or username from URL");
      
      const endpoints = [
        `https://graph.facebook.com/${usernameOrId}?fields=id&access_token=350685531728|62f8ce9f74b12f84c123cc23437a4a32`,
        `https://graph.facebook.com/v15.0/${usernameOrId}?fields=id&access_token=6628568379|c1e620fa708a1d5696fb991c1bde5662`
      ];
      
      for (const endpoint of endpoints) {
        try {
          const res = await axios.get(endpoint, { timeout: 10000 });
          if (res.data?.id) return res.data.id;
        } catch (e) {
          console.warn(`Failed with endpoint ${endpoint}: ${e.message}`);
        }
      }
      
      throw new Error("All API endpoints failed to resolve UID");
    } catch (err) {
      logger.err(`Failed to find UID: ${err.message}`, "UID_ERROR");
      throw err;
    }
  },

  humanDelay: async (customMin, customMax) => {
    const config = global.config || defaultConfigContent;
    const min = customMin || config.humanLikeDelay.min;
    const max = customMax || config.humanLikeDelay.max;
    const delay = Math.floor(Math.random() * (max - min + 1)) + min;
    
    if (config.security?.enableRandomDelays !== false) {
      logger.log(`Adding human-like delay of ${delay}ms...`, "DELAY");
      await new Promise(resolve => setTimeout(resolve, delay));
    }
    return true;
  },

  saveSession: async (api, filePath = "appstate.json") => {
    try {
      if (!api.getAppState) {
        throw new Error("API does not support getAppState");
      }
      
      const appState = api.getAppState();
      if (!appState || !Array.isArray(appState)) {
        throw new Error("Invalid appState format");
      }
      
      let data = JSON.stringify(appState, null, 2);
      
      if (global.config.encryptSt) {
        const key = process.env.REPL_OWNER || process.env.PROCESSOR_IDENTIFIER || "default-encryption-key";
        data = await utils.encryptState(data, key);
      }
      
      await fs.writeFile(filePath, data);
      logger.log("Session saved successfully", "SESSION");
      return true;
    } catch (err) {
      logger.err(`Failed to save session: ${err.message}`, "SESSION_ERROR");
      return false;
    }
  },

  enhancedLogin: async (credentials, options = {}) => {
    const maxAttempts = options.maxRetries || 3;
    const retryDelay = options.retryDelay || 30000;
    
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        logger.log(`Attempting login (attempt ${attempt}/${maxAttempts})`, "LOGIN");
        const api = await performLogin(credentials, options);
        await verifyLogin(api);
        logger.log("Login successful", "LOGIN_SUCCESS");
        return api;
      } catch (err) {
        logger.err(`Login attempt ${attempt} failed: ${err.message}`, "LOGIN_FAIL");
        
        if (attempt >= maxAttempts) {
          logger.log("Falling back to puppeteer login", "LOGIN_FALLBACK");
          return await puppeteerLogin(credentials);
        }
        
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  },

  puppeteerLogin: async ({ email, password }) => {
    logger.log("Starting puppeteer login process", "PUPPETEER_LOGIN");
    
    try {
      const browser = await puppeteer.launch({
        headless: false,
        args: global.config.FCAOption.browserArgs || []
      });
      
      const page = await browser.newPage();
      await page.setViewport({ width: 1366, height: 768 });
      await page.setUserAgent(global.config.FCAOption.userAgent || userAgents[0]);
      
      await page.goto('https://facebook.com', { 
        waitUntil: 'networkidle2',
        timeout: 60000 
      });
      await utils.humanDelay(2000, 5000);
      
      await page.type('#email', email, { delay: 100 });
      await utils.humanDelay(500, 1500);
      await page.type('#pass', password, { delay: 80 });
      await utils.humanDelay(1000, 3000);
      
      await page.click('[name="login"]');
      await utils.humanDelay(5000, 10000);
      
      try {
        await page.waitForNavigation({ timeout: 30000 });
      } catch (e) {
        logger.warn("Navigation timeout exceeded, continuing anyway", "LOGIN_WARN");
      }
      
      const cookies = await page.cookies();
      const appState = cookies.map(cookie => ({
        key: cookie.name,
        value: cookie.value,
        domain: cookie.domain,
        path: cookie.path,
        expires: cookie.expires,
        secure: cookie.secure,
        httponly: cookie.httpOnly
      }));
      
      await utils.saveSession({ getAppState: () => appState });
      await browser.close();
      
      return await performLogin({ appState }, global.config.FCAOption);
    } catch (err) {
      logger.err(`Puppeteer login failed: ${err.message}`, "PUPPETEER_LOGIN_FAIL");
      throw err;
    }
  },

  verifyLogin: async (api) => {
    try {
      await api.getThreadList(1, null, ['INBOX']);
      return true;
    } catch (err) {
      throw new Error(`Login verification failed: ${err.message}`);
    }
  },

  decryptState: (encryptedState, key) => {
    logger.warn("DecryptState is a placeholder. Implement actual decryption if 'encryptSt' is true.", "DECRYPT_WARN");
    return encryptedState;
  },

  encryptState: (state, key) => {
    logger.warn("EncryptState is a placeholder. Implement actual encryption if 'encryptSt' is true.", "ENCRYPT_WARN");
    return state;
  },

  restartBot: async (api, reason = "Scheduled restart") => {
    logger.warn(`Restarting bot: ${reason}`, "RESTART");
    savePersistentData({
      installedCommands: global.installedCommands,
      adminMode: global.adminMode
    });

    if (global.config.autoRestart.notifyAdmins && global.config.ADMINBOT && global.config.ADMINBOT.length > 0) {
      for (const adminID of global.config.ADMINBOT) {
        try {
          await api.sendMessage(
            `♻️ Bot is restarting automatically as scheduled.\nReason: ${reason}\nIt should be back online shortly.`,
            adminID
          );
        } catch (e) {
          logger.err(`Failed to send restart notification to admin ${adminID}: ${e.message}`, "RESTART_NOTIFY");
        }
      }
    }

    await new Promise(resolve => setTimeout(resolve, 2000));
    process.on('exit', () => {
      spawn(process.argv.shift(), process.argv, {
        cwd: process.cwd(),
        detached: true,
        stdio: 'inherit'
      });
    });
    process.exit();
  },

  checkHeartbeat: async (api) => {
    if (!global.config.heartbeat?.enabled) return true;
    
    try {
      const startTime = Date.now();
      await Promise.race([
        api.getThreadList(1, null, ['INBOX']),
        new Promise((_, reject) => {
          setTimeout(() => {
            reject(new Error('Heartbeat timeout'));
          }, global.config.heartbeat.timeout || 60000);
        })
      ]);
      const responseTime = Date.now() - startTime;
      logger.log(`Heartbeat check passed. Response time: ${responseTime}ms`, "HEARTBEAT");
      return true;
    } catch (e) {
      logger.err(`Heartbeat check failed: ${e.message}`, "HEARTBEAT_ERROR");
      return false;
    }
  }
};

// Persistent storage system
const DATA_DIR = path.join(__dirname, 'data');
const PERSISTENT_FILE = path.join(DATA_DIR, 'persistent.json');
const SESSION_FILE = path.join(DATA_DIR, 'session_backup.json');

fs.ensureDirSync(DATA_DIR);

function loadPersistentData() {
  try {
    if (fs.existsSync(PERSISTENT_FILE)) {
      const data = JSON.parse(fs.readFileSync(PERSISTENT_FILE, 'utf8'));
      
      if (!data.installedCommands || !Array.isArray(data.installedCommands)) {
        data.installedCommands = [];
      }
      if (!data.adminMode || typeof data.adminMode !== 'object') {
        data.adminMode = { enabled: false, adminUserIDs: [] };
      }
      if (!data.sessions) {
        data.sessions = {};
      }
      
      return data;
    }
  } catch (e) {
    logger.err(`Error loading persistent data: ${e.message}`, "STORAGE_ERROR");
  }
  
  return {
    installedCommands: [],
    adminMode: { enabled: false, adminUserIDs: [] },
    sessions: {}
  };
}

function savePersistentData(data) {
  try {
    const saveData = {
      installedCommands: Array.isArray(data.installedCommands) ? data.installedCommands : [],
      adminMode: {
        enabled: !!data.adminMode?.enabled,
        adminUserIDs: Array.isArray(data.adminMode?.adminUserIDs) ? data.adminMode.adminUserIDs : []
      },
      sessions: data.sessions || {}
    };
    
    fs.writeFileSync(PERSISTENT_FILE, JSON.stringify(saveData, null, 2));
    
    if (fs.existsSync('appstate.json')) {
      const appState = fs.readFileSync('appstate.json', 'utf8');
      saveData.sessions.lastAppState = appState;
      fs.writeFileSync(SESSION_FILE, JSON.stringify(saveData, null, 2));
    }
    
    return true;
  } catch (e) {
    logger.err(`Error saving persistent data: ${e.message}`, "STORAGE_ERROR");
    return false;
  }
}

const persistentData = loadPersistentData();

// Creator protection
const CREATOR_NAME = "Hassan";
let creatorName = CREATOR_NAME;

function protectCreatorName() {
  if (creatorName !== CREATOR_NAME) {
    console.error(chalk.red(`CRITICAL ERROR: CREATOR NAME CHANGED FROM "${CREATOR_NAME}" TO "${creatorName}"`));
    console.error(chalk.red("THIS IS NOT ALLOWED. THE BOT WILL NOW CRASH."));
    process.exit(1);
  }
}

// Enhanced logger
const logger = {
  log: (message, tag = "INFO") => {
    protectCreatorName();
    const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
    console.log(`[${timestamp}] ${chalk.blue(`[${tag}]`)} ${message}`);
  },
  loader: (message, tag = "LOADER") => {
    protectCreatorName();
    const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
    console.log(`[${timestamp}] ${chalk.cyan(`[${tag}]`)} ${message}`);
  },
  err: (message, tag = "ERROR") => {
    protectCreatorName();
    const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
    console.error(`[${timestamp}] ${chalk.red(`[${tag}]`)} ${message}`);
  },
  warn: (message, tag = "WARN") => {
    protectCreatorName();
    const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
    console.warn(`[${timestamp}] ${chalk.yellow(`[${tag}]`)} ${message}`);
  },
  debug: (message, tag = "DEBUG") => {
    if (global.config?.DeveloperMode) {
      protectCreatorName();
      const timestamp = moment().format("YYYY-MM-DD HH:mm:ss");
      console.log(`[${timestamp}] ${chalk.magenta(`[${tag}]`)} ${message}`);
    }
  }
};

// Thread data manager
function createThreadDataManager() {
    const threadDataStore = new Map();
    const backupInterval = 3600000;
    
    setInterval(() => {
        try {
            const backupFile = path.join(DATA_DIR, 'thread_data_backup.json');
            const backupData = Array.from(threadDataStore.entries());
            fs.writeFileSync(backupFile, JSON.stringify(backupData, null, 2));
            logger.debug("Thread data backup completed", "DATA_BACKUP");
        } catch (e) {
            logger.err(`Thread data backup failed: ${e.message}`, "DATA_BACKUP_ERROR");
        }
    }, backupInterval);
    
    return {
        get: async (threadID, path) => {
            try {
                let current = threadDataStore.get(threadID);
                if (!current) return undefined;
                
                const pathParts = path.split('.');
                for (const part of pathParts) {
                    if (current && typeof current === 'object' && current.has(part)) {
                        current = current.get(part);
                    } else {
                        return undefined;
                    }
                }
                return current;
            } catch (e) {
                logger.err(`Error getting thread data: ${e.message}`, "THREAD_DATA_ERROR");
                return undefined;
            }
        },
        set: async (threadID, value, path) => {
            try {
                if (!threadDataStore.has(threadID)) {
                    threadDataStore.set(threadID, new Map());
                }
                
                let current = threadDataStore.get(threadID);
                const pathParts = path.split('.');
                
                for (let i = 0; i < pathParts.length; i++) {
                    const part = pathParts[i];
                    if (i === pathParts.length - 1) {
                        current.set(part, value);
                    } else {
                        if (!current.has(part) || !(current.get(part) instanceof Map)) {
                            current.set(part, new Map());
                        }
                        current = current.get(part);
                    }
                }
                return true;
            } catch (e) {
                logger.err(`Error setting thread data: ${e.message}`, "THREAD_DATA_ERROR");
                return false;
            }
        },
        delete: async (threadID, path) => {
            try {
                let current = threadDataStore.get(threadID);
                if (!current) return false;
                
                const pathParts = path.split('.');
                for (let i = 0; i < pathParts.length; i++) {
                    const part = pathParts[i];
                    if (i === pathParts.length - 1) {
                        current.delete(part);
                    } else {
                        if (!current.has(part) || !(current.get(part) instanceof Map)) {
                            return false;
                        }
                        current = current.get(part);
                    }
                }
                
                if (threadDataStore.get(threadID)?.size === 0) {
                    threadDataStore.delete(threadID);
                }
                return true;
            } catch (e) {
                logger.err(`Error deleting thread data: ${e.message}`, "THREAD_DATA_ERROR");
                return false;
            }
        },
        backup: () => {
            return Array.from(threadDataStore.entries());
        },
        restore: (backupData) => {
            try {
                threadDataStore.clear();
                for (const [key, value] of backupData) {
                    threadDataStore.set(key, value);
                }
                return true;
            } catch (e) {
                logger.err(`Error restoring thread data: ${e.message}`, "THREAD_DATA_ERROR");
                return false;
            }
        }
    };
}

// Listener function
const listen = ({ api }) => {
    return async (error, event) => {
        try {
            await utils.humanDelay();
            
            if (error) {
                logger.err(`Listen error: ${error.message}`, "LISTENER_ERROR");
                
                if (error.error === 'Not logged in' || error.error === 'Login approval needed') {
                    logger.warn("Session expired or invalid. Attempting to re-login...", "SESSION_EXPIRED");
                    
                    try {
                        const newApi = await utils.enhancedLogin(
                            { appState: api.getAppState() },
                            global.config.FCAOption
                        );
                        global.client.api = newApi;
                        logger.log("Re-login successful", "SESSION_RESTORED");
                        return;
                    } catch (loginErr) {
                        logger.err(`Re-login failed: ${loginErr.message}`, "SESSION_RESTORE_FAIL");
                    }
                }
                return;
            }

            if (!event || typeof event !== 'object') {
                logger.err("Received invalid event object", "EVENT_VALIDATION");
                return;
            }

            if (!event.type && !event.logMessageType) {
                logger.debug("Event missing type information - skipping", "EVENT_VALIDATION");
                return;
            }

            if (event.threadID && typeof event.threadID !== 'string') {
                logger.err("Invalid threadID in event", "EVENT_VALIDATION");
                return;
            }

            if (event.attachments && event.attachments.length > 0) {
                const videoAttachments = event.attachments.filter(att => att.type === "video");
                if (videoAttachments.length > 0) {
                    logger.log(`Received video message with ${videoAttachments.length} video(s)`, "VIDEO_MESSAGE");
                    return;
                }
            }

            if (event.type) {
                logger.log(`Received event type: ${event.type}`, "EVENT_RECEIVED");
            } else if (event.logMessageType) {
                logger.log(`Received log message event: ${event.logMessageType}`, "LOG_EVENT");
            }

            if (event.logMessageType) {
                global.client.events.forEach(async (eventModule) => {
                    if (eventModule.config.eventType && eventModule.config.eventType.includes("event") && eventModule.onChat) {
                        try {
                            logger.log(`Executing event handler for logMessageType: ${event.logMessageType} for module: ${eventModule.config.name}`, "LOG_EVENT_HANDLER");
                            await eventModule.onChat({
                                api,
                                event,
                                threadsData: global.data.threads,
                                getLang: global.getText,
                                commandName: eventModule.config.name
                            });
                        } catch (e) {
                            logger.err(`Error executing log event handler for '${eventModule.config.name}': ${e.message}`, "LOG_EVENT_EXEC_ERROR");
                        }
                    }
                });
                if (event.logMessageType === "log:subscribe" && event.logMessageData?.addedParticipants?.some(i => i.userFbId == api.getCurrentUserID())) {
                    return;
                }
            }

            if (global.adminMode.enabled && event.senderID && !global.adminMode.adminUserIDs.includes(event.senderID)) {
                return;
            }

            if (event.type === "message_reaction") {
                if (!event.messageID) {
                    logger.err("Message reaction event missing messageID", "EVENT_ERROR");
                    return;
                }

                const currentConfig = global.config || defaultConfigContent;
                const unsendEmojis = currentConfig.unsendEmojis || ["🤓", "🚫"];
                
                if (unsendEmojis.includes(event.reaction)) {
                    try {
                        const isAdmin = global.config.ADMINBOT.includes(event.senderID);
                        
                        let isParticipant = false;
                        if (!isAdmin) {
                            try {
                                const threadInfo = await api.getThreadInfo(event.threadID);
                                isParticipant = threadInfo.participantIDs.includes(event.senderID);
                            } catch (e) {
                                logger.err(`Error getting thread info: ${e.message}`, "THREAD_INFO_ERROR");
                            }
                        }
                        
                        if (isAdmin || isParticipant) {
                            logger.log(`Unsend triggered by ${event.senderID} with reaction ${event.reaction} on message ${event.messageID}`, "UNSEND_REACTION");
                            await api.unsendMessage(event.messageID);
                            return;
                        } else {
                            logger.log(`User ${event.senderID} tried to unsend message ${event.messageID} but lacks permission`, "UNSEND_PERMISSION_DENIED");
                            return;
                        }
                    } catch (e) {
                        logger.err(`Error processing unsend reaction: ${e.message}`, "UNSEND_REACTION_ERROR");
                    }
                }

                const reactionHandler = global.client.onReaction.get(event.messageID);
                if (reactionHandler) {
                    if (reactionHandler.commandName === "prefix_change") {
                        if (event.userID !== reactionHandler.author) {
                            return api.sendMessage("Only the command user can confirm prefix change.", event.threadID);
                        }

                        await global.data.threads.set(event.threadID, reactionHandler.newPrefix, "data.prefix");
                        return api.sendMessage(
                            `✅ Prefix changed to: ${reactionHandler.newPrefix}\nSystem prefix remains: ${global.config.PREFIX}`,
                            event.threadID
                        );
                    }

                    const module = global.client.commands.get(reactionHandler.commandName) || global.client.events.get(reactionHandler.commandName);
                    if (module && module.onReaction) {
                        try {
                            logger.log(`Executing reaction handler for ${module.config.name} (message ID: ${event.messageID})`, "REACTION_EVENT");
                            await utils.humanDelay();
                            await module.onReaction({
                                api,
                                event,
                                Reaction: reactionHandler,
                                threadsData: global.data.threads,
                                getLang: global.getText
                            });
                        } catch (e) {
                            logger.err(`Error executing reaction handler for '${module.config.name}': ${e.message}`, "REACTION_EXEC_ERROR");
                            await api.sendMessage(
                                `⚠️ An error occurred while processing reaction:\n${e.message}`,
                                event.threadID
                            );
                        }
                    }
                }
                return;
            }

            global.api = api;
            global.api.handleReply = global.api.handleReply || new Map();

            if (event.type === "message" || event.type === "message_reply") {
                if (!event.body && (!event.attachments || event.attachments.length === 0)) {
                    logger.log("Received empty message with no attachments", "EMPTY_MESSAGE");
                    return;
                }

                const lowerCaseBody = event.body ? event.body.toLowerCase() : '';
                const systemPrefix = global.config.PREFIX;
                let threadPrefix = await global.data.threads.get(event.threadID, "data.prefix") || systemPrefix;
                let commandFoundAndExecuted = false;

                const prefixCommandRegex = /^(?:prefix|\?prefix|Prefix)\s*$/i;
                if (prefixCommandRegex.test(event.body.trim())) {
                    await utils.humanDelay();
                    return api.sendMessage(
                        `🌐 System prefix: ${systemPrefix}\n🛸 Current chat prefix: ${threadPrefix}`,
                        event.threadID,
                        event.messageID
                    );
                }

                const prefixChangeRegex = /^(?:prefix|\?prefix|Prefix)\s+(\S+)/i;
                const prefixChangeMatch = event.body.match(prefixChangeRegex);
                if (prefixChangeMatch) {
                    const newPrefix = prefixChangeMatch[1];

                    if (newPrefix.length > 3) {
                        return api.sendMessage("Prefix must be 1-3 characters long.", event.threadID, event.messageID);
                    }

                    const confirmationMessage = await api.sendMessage(
                        `Please react to this message to confirm changing prefix to: ${newPrefix}`,
                        event.threadID,
                        (err, msgInfo) => {
                            if (err) return;
                            global.client.onReaction.set(msgInfo.messageID, {
                                commandName: "prefix_change",
                                threadID: event.threadID,
                                author: event.senderID,
                                newPrefix: newPrefix
                            });
                        }
                    );
                    return;
                }

                if (event.type === "message_reply") {
                    if (!event.messageReply || !event.messageReply.messageID) {
                        logger.err("Invalid reply event - missing messageReply data", "REPLY_ERROR");
                        return;
                    }

                    const repliedToMessageID = event.messageReply.messageID;
                    const threadID = event.threadID;
                    const replierSenderID = event.senderID;

                    const replyHandler = global.api.handleReply.get(repliedToMessageID);

                    if (replyHandler && replyHandler.threadID === threadID) {
                        const command = global.client.commands.get(replyHandler.name);

                        if (command && typeof command.onReply === "function") {
                            try {
                                await utils.humanDelay();

                                await command.onReply({
                                    api,
                                    event,
                                    Reply: replyHandler,
                                    message: {
                                        reply: async (msg) => {
                                            await utils.humanDelay();
                                            api.sendMessage(msg, threadID, event.messageID);
                                        },
                                        unsend: async (msgID) => {
                                            await utils.humanDelay();
                                            api.unsendMessage(msgID);
                                        }
                                    },
                                    global,
                                    threadsData: global.data.threads,
                                    getLang: global.getText,
                                    commandName: command.config.name
                                });

                                commandFoundAndExecuted = true;
                            } catch (e) {
                                console.error(`[REPLY_ERROR] ${e.message}`);
                                await utils.humanDelay();
                                api.sendMessage(`❌ Error while processing reply for '${replyHandler.name}':\n${e.message}`, threadID, event.messageID);
                                commandFoundAndExecuted = true;
                            }
                        } else {
                            global.api.handleReply.delete(repliedToMessageID);
                        }
                    }
                }

                if (commandFoundAndExecuted) return;

                if (lowerCaseBody.startsWith(threadPrefix)) {
                    const args = event.body.slice(threadPrefix.length).trim().split(/\s+/);
                    const commandName = args.shift().toLowerCase();

                    const command =
                        global.client.commands.get(commandName) ||
                        [...global.client.commands.values()].find(cmd => cmd.config.aliases?.includes(commandName));

                    if (command && typeof command.onStart === "function") {
                        try {
                            await utils.humanDelay();
                            await command.onStart({
                                api,
                                event,
                                args,
                                message: {
                                    reply: async (msg) => {
                                        await utils.humanDelay();
                                        api.sendMessage(msg, event.threadID, event.messageID);
                                    },
                                    unsend: async (msgID) => {
                                        await utils.humanDelay();
                                        api.unsendMessage(msgID);
                                    }
                                },
                                global,
                                threadsData: global.data.threads,
                                getLang: global.getText,
                                commandName: command.config.name
                            });

                            commandFoundAndExecuted = true;
                        } catch (err) {
                            console.error(`[COMMAND_ERROR] Error in onStart for '${commandName}': ${err.message}`);
                            api.sendMessage(`❌ Error while executing '${commandName}' command:\n${err.message}`, event.threadID, event.messageID);
                        }
                    }
                }

                for (const cmdNameLower of global.client.nonPrefixCommands) {
                    if (lowerCaseBody === cmdNameLower || lowerCaseBody.startsWith(`${cmdNameLower} `)) {
                        let foundCommand = null;
                        for (const [key, cmdModule] of global.client.commands.entries()) {
                            if (key.toLowerCase() === cmdNameLower && (cmdModule.config.usePrefix === false || cmdModule.config.usePrefix === "both")) {
                                foundCommand = cmdModule;
                                break;
                            }
                        }

                        if (foundCommand) {
                            if (global.adminMode.enabled && event.senderID && !global.adminMode.adminUserIDs.includes(event.senderID)) {
                                await utils.humanDelay();
                                api.sendMessage("🔒 The bot is in Admin-only mode. You can't use commands right now.", event.threadID, event.messageID);
                                commandFoundAndExecuted = true;
                                break;
                            }

                            const promptText = lowerCaseBody.startsWith(`${cmdNameLower} `) ? event.body.slice(cmdNameLower.length + 1).trim() : "";
                            const args = promptText.split(/ +/).filter(Boolean);

                            if (foundCommand.config.hasPermssion !== undefined && foundCommand.config.hasPermssion > 0) {
                                if (foundCommand.config.hasPermssion === 1 && event.senderID && !global.adminMode.adminUserIDs.includes(event.senderID)) {
                                    await utils.humanDelay();
                                    api.sendMessage("You don't have permission to use this command.", event.threadID, event.messageID);
                                    commandFoundAndExecuted = true;
                                    break;
                                }
                            }

                            try {
                                logger.log(`Executing non-prefix command: ${foundCommand.config.name}`, "NON_PREFIX_COMMAND");
                                await utils.humanDelay();
                                const runFunction = foundCommand.run || foundCommand.onStart;
                                if (runFunction) {
                                    const info = {};
                                    await runFunction({
                                        api, event, args, global, prompt: promptText,
                                        threadsData: global.data.threads, getLang: global.getText, commandName: foundCommand.config.name,
                                        message: {
                                            reply: async (msg, cb) => {
                                                await utils.humanDelay();
                                                const messageInfo = await api.sendMessage(msg, event.threadID, (err, msgInfo) => {
                                                    if (!err && msgInfo) {
                                                        info.messageID = msgInfo.messageID;
                                                        info.threadID = event.threadID;
                                                    }
                                                    if (cb) cb(err, msgInfo);
                                                });
                                                if (messageInfo && messageInfo.messageID) {
                                                    info.messageID = messageInfo.messageID;
                                                    info.threadID = event.threadID;
                                                }
                                            },
                                            unsend: async (mid) => { await utils.humanDelay(); api.unsendMessage(mid); }
                                        },
                                        info
                                    });

                                    if (info.messageID) {
                                        global.client.handleReply.set(info.messageID, {
                                            name: foundCommand.config.name,
                                            threadID: event.threadID,
                                            author: event.senderID
                                        });
                                        logger.log(`Registered reply handler for message ID: ${info.messageID} (Command: ${foundCommand.config.name})`, "REPLY_REGISTER");
                                    }
                                }
                                commandFoundAndExecuted = true;
                            } catch (e) {
                                logger.err(`Error executing non-prefix command '${foundCommand.config.name}': ${e.message}`, "NON_PREFIX_EXEC");
                                await utils.humanDelay();
                                api.sendMessage(`An error occurred while running the '${foundCommand.config.name}' command:\n${e.message}`, event.threadID, event.messageID);
                            }
                            break;
                        }
                    }
                }

                if (commandFoundAndExecuted) {
                    return;
                }

                if (event.body && event.body.startsWith(threadPrefix)) {
                    const args = event.body.slice(threadPrefix.length).trim().split(/ +/);
                    const commandName = args.shift()?.toLowerCase();

                    if (!commandName) {
                        await utils.humanDelay();
                        return api.sendMessage(
                            `⚠️ The command you are using does not exist.\n` +
                            `Type ${threadPrefix}help to see all available commands.`,
                            event.threadID,
                            event.messageID
                        );
                    }

                    const command = global.client.commands.get(commandName);

                    if (!command) {
                        await utils.humanDelay();
                        return api.sendMessage(
                            `⚠️ The command "${threadPrefix}${commandName}" does not exist.\n` +
                            `Type ${threadPrefix}help to see all available commands.`,
                            event.threadID,
                            event.messageID
                        );
                    }

                    if (command.config.usePrefix === false) {
                        await utils.humanDelay();
                        return api.sendMessage(
                            `⚠️ The command "${command.config.name}" does not require a prefix.\n` +
                            `Just type "${command.config.name} ${command.config.guide ? command.config.guide.en.split('\n')[0].replace(/.*<prompt>\s*/, '').trim() : ''}" to use it.`,
                            event.threadID,
                            event.messageID
                        );
                    }

                    if (global.adminMode.enabled && event.senderID && !global.adminMode.adminUserIDs.includes(event.senderID)) {
                        await utils.humanDelay();
                        return api.sendMessage("🔒 The bot is in Admin-only mode. You can't use commands right now.", event.threadID, event.messageID);
                    }

                    try {
                        if (command.config.hasPermssion !== undefined && command.config.hasPermssion > 0) {
                            if (command.config.hasPermssion === 1 && event.senderID && !global.adminMode.adminUserIDs.includes(event.senderID)) {
                                await utils.humanDelay();
                                api.sendMessage("You don't have permission to use this command.", event.threadID, event.messageID);
                                return;
                            }
                        }

                        logger.log(`Executing command: ${command.config.name}`, "COMMAND");
                        await utils.humanDelay();
                        const prefixedPrompt = args.join(" ");
                        const runFunction = command.run || command.onStart;
                        if (runFunction) {
                            const info = {};
                            await runFunction({
                                api, event, args, global, prompt: prefixedPrompt,
                                threadsData: global.data.threads, getLang: global.getText, commandName: command.config.name,
                                message: {
                                    reply: async (msg, cb) => {
                                        await utils.humanDelay();
                                        const messageInfo = await api.sendMessage(msg, event.threadID, (err, msgInfo) => {
                                            if (!err && msgInfo) {
                                                info.messageID = msgInfo.messageID;
                                                info.threadID = event.threadID;
                                            }
                                            if (cb) cb(err, msgInfo);
                                        });
                                        if (messageInfo && messageInfo.messageID) {
                                            info.messageID = messageInfo.messageID;
                                            info.threadID = event.threadID;
                                        }
                                    },
                                    unsend: async (mid) => { await utils.humanDelay(); api.unsendMessage(mid); }
                                },
                                info
                            });

                            if (info.messageID) {
                                global.client.handleReply.set(info.messageID, {
                                    name: command.config.name,
                                    threadID: event.threadID,
                                    author: event.senderID
                                });
                                logger.log(`Registered reply handler for message ID: ${info.messageID} (Command: ${command.config.name})`, "REPLY_REGISTER");
                            }
                        }
                    } catch (e) {
                        logger.err(`Error executing command '${command.config.name}': ${e.message}`, "COMMAND_EXEC");
                        await utils.humanDelay();
                        api.sendMessage(`An error occurred while running the '${command.config.name}' command:\n${e.message}`, event.threadID, event.messageID);
                    }
                    return;
                }

                global.client.events.forEach(async (eventModule) => {
                    if (eventModule.config.eventType && eventModule.config.eventType.includes("message") && eventModule.onChat) {
                        try {
                            await eventModule.onChat({
                                api,
                                event,
                                threadsData: global.data.threads,
                                getLang: global.getText,
                                commandName: eventModule.config.name
                            });
                        } catch (e) {
                            logger.err(`Error executing onChat event for '${eventModule.config.name}': ${e.message}`, "ON_CHAT_EXEC_ERROR");
                            await api.sendMessage(
                                `⚠️ An error occurred in event handler:\n${e.message}`,
                                event.threadID
                            );
                        }
                    }
                });
            }
        } catch (err) {
            logger.err(`Error in listener function: ${err.message}`, "LISTENER_ERROR");
            if (event && event.threadID) {
                await api.sendMessage(
                    `⚠️ A system error occurred:\n${err.message}`,
                    event.threadID
                );
            }
        }
    };
};

// Custom scripts
const customScript = ({ api }) => {
    logger.log("Initializing enhanced custom scripts...", "CUSTOM_SCRIPTS");
    
    const acceptPendingConfig = {
        status: true,
        time: 30,
        maxAttempts: 3
    };

    function acceptPending(config) {
        if (config.status) {
            cron.schedule(`*/${config.time} * * * *`, async () => {
                let attempts = 0;
                let success = false;
                
                while (attempts < config.maxAttempts && !success) {
                    try {
                        attempts++;
                        const list = [
                            ...(await api.getThreadList(1, null, ['PENDING'])),
                            ...(await api.getThreadList(1, null, ['OTHER']))
                        ];
                        
                        if (list[0]) {
                            await utils.humanDelay();
                            await api.sendMessage(
                                'You have been approved for the queue. (This is an automated message)', 
                                list[0].threadID
                            );
                            logger.log(`Approved pending thread: ${list[0].threadID}`, "AUTO_PENDING");
                            success = true;
                        } else {
                            logger.debug("No pending threads to approve", "AUTO_PENDING");
                            success = true;
                        }
                    } catch (e) {
                        logger.err(`Error accepting pending messages (attempt ${attempts}/${config.maxAttempts}): ${e.message}`, "AUTO_PENDING_ERROR");
                        if (attempts < config.maxAttempts) {
                            await utils.humanDelay(5000, 10000);
                        }
                    }
                }
            }, {
                scheduled: true,
                timezone: "Asia/Dhaka"
            });
        }
    }
    
    acceptPending(acceptPendingConfig);

    if (global.config.randomActivity?.status) {
        cron.schedule('*/1 * * * *', async () => {
            try {
                const minInterval = global.config.randomActivity.intervalMin;
                const maxInterval = global.config.randomActivity.intervalMax;
                const randomMinutes = Math.floor(Math.random() * (maxInterval - minInterval + 1)) + minInterval;

                if (Date.now() - global.client.lastActivityTime > randomMinutes * 60 * 1000) {
                    logger.log("Performing random human-like activity...", "ACTIVITY");
                    
                    let threadList;
                    try {
                        threadList = await api.getThreadList(5, null, ['INBOX']);
                    } catch (e) {
                        logger.err(`Error getting thread list: ${e.message}`, "ACTIVITY_ERROR");
                        return;
                    }

                    if (threadList.length > 0) {
                        const randomThread = threadList[Math.floor(Math.random() * threadList.length)];
                        const activities = [];
                        
                        if (global.config.randomActivity.activities.includes("markRead")) {
                            activities.push(async () => {
                                await utils.humanDelay();
                                try {
                                    const messages = await api.getThreadHistory(randomThread.threadID, 5);
                                    if (messages?.length > 0) {
                                        const unreadMessages = messages.filter(msg => !msg.isRead);
                                        if (unreadMessages.length > 0) {
                                            const msg = unreadMessages[Math.floor(Math.random() * unreadMessages.length)];
                                            await api.markAsRead(msg.messageID);
                                            logger.log(`Marked message as read in thread ${randomThread.threadID}`, "ACTIVITY");
                                        }
                                    }
                                } catch (e) {
                                    logger.err(`Error marking as read: ${e.message}`, "ACTIVITY_ERROR");
                                }
                            });
                        }
                        
                        if (global.config.randomActivity.activities.includes("goOffline")) {
                            activities.push(async () => {
                                await utils.humanDelay();
                                try {
                                    await api.setOptions({ online: false });
                                    logger.log("Temporarily set bot offline", "ACTIVITY");
                                    await utils.humanDelay(3000, 8000);
                                    await api.setOptions({ online: true });
                                    logger.log("Set bot back online", "ACTIVITY");
                                } catch (e) {
                                    logger.err(`Error changing online status: ${e.message}`, "ACTIVITY_ERROR");
                                }
                            });
                        }
                        
                        if (activities.length > 0) {
                            const randomActivity = activities[Math.floor(Math.random() * activities.length)];
                            await randomActivity();
                            global.client.lastActivityTime = Date.now();
                        }
                    }
                }
            } catch (e) {
                logger.err(`Error in random activity scheduler: ${e.message}`, "ACTIVITY_ERROR");
            }
        }, {
            scheduled: true,
            timezone: "Asia/Dhaka"
        });
    }

    if (global.config.autoRestart?.enabled) {
        cron.schedule(global.config.autoRestart.schedule, async () => {
            await utils.restartBot(api, "Scheduled restart");
        }, {
            scheduled: true,
            timezone: "Asia/Dhaka"
        });
    }

    if (global.config.heartbeat?.enabled) {
        const interval = global.config.heartbeat.interval || 300000;
        const maxFailedAttempts = global.config.heartbeat.maxFailures || 3;
        let failedAttempts = 0;

        setInterval(async () => {
            try {
                const isHealthy = await utils.checkHeartbeat(api);
                if (!isHealthy) {
                    failedAttempts++;
                    logger.warn(`Heartbeat check failed (attempt ${failedAttempts}/${maxFailedAttempts})`, "HEARTBEAT_WARN");
                    
                    if (failedAttempts >= maxFailedAttempts) {
                        logger.err("Max failed heartbeat attempts reached. Restarting bot...", "HEARTBEAT_ERROR");
                        await utils.restartBot(api, "Heartbeat failure");
                    }
                } else {
                    failedAttempts = 0;
                }
            } catch (e) {
                logger.err(`Error in heartbeat check: ${e.message}`, "HEARTBEAT_ERROR");
                failedAttempts++;
                
                if (failedAttempts >= maxFailedAttempts) {
                    logger.err("Max failed heartbeat attempts reached. Restarting bot...", "HEARTBEAT_ERROR");
                    await utils.restartBot(api, "Heartbeat failure");
                }
            }
        }, interval);
    }
};

// Appstate management
const appStatePlaceholder = "(›^-^)›";
const fbstateFile = "appstate.json";

const userAgents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.113 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1"
];

let loginAttempts = 0;
let isLoggingIn = false;
let lastLoginAttempt = 0;
let isBlocked = false;
let lastBlockCheck = 0;
let server = null;

async function checkBlockStatus(api) {
    try {
        if (Date.now() - lastBlockCheck < 300000) {
            return isBlocked;
        }
        
        lastBlockCheck = Date.now();
        const threadList = await api.getThreadList(1, null, ['INBOX']);
        
        if (isBlocked) {
            logger.log("Account is no longer blocked", "BLOCK_STATUS");
            isBlocked = false;
        }
        return false;
    } catch (e) {
        if (e.message.includes('blocked') || e.message.includes('restricted') || 
            e.message.includes('temporarily unavailable')) {
            if (!isBlocked) {
                logger.err("Account appears to be blocked by Facebook", "BLOCK_STATUS");
            }
            isBlocked = true;
            return true;
        }
        return false;
    }
}

const delayedLog = async (message) => {
    const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    for (const char of message) {
        process.stdout.write(char);
        await delay(50);
    }
    console.log();
};

const showMessageAndExit = async (message) => {
    await delayedLog(message);
    setTimeout(() => {
        process.exit(0);
    }, 10000);
};

let packageJson;
try {
    packageJson = require("./package.json");
} catch (error) {
    logger.err("Error loading package.json. Please ensure it exists and is valid JSON.", "PACKAGE_JSON_ERROR");
    process.exit(1);
}

function normalizeVersion(version) {
    return version.replace(/^\^/, "");
}

async function checkAndUpdateDependencies() {
    if (global.config.UPDATE && global.config.UPDATE.Package) {
        try {
            for (const [dependency, currentVersion] of Object.entries(
                    packageJson.dependencies
                )) {
                if (global.config.UPDATE.EXCLUDED.includes(dependency)) {
                    logger.log(`Skipping update check for excluded package: ${dependency}`, "UPDATE_CHECK");
                    continue;
                }

                const latestVersion = await check(dependency);
                const normalizedCurrentVersion = normalizeVersion(currentVersion);

                if (semver.neq(normalizedCurrentVersion, latestVersion)) {
                    logger.warn(
                        `There is a newer version ${chalk.yellow(`(^${latestVersion})`)} available for ${chalk.yellow(dependency)}. ` +
                        `Please manually update it by running 'npm install ${dependency}@latest'`, "MANUAL_UPDATE"
                    );
                } else {
                    logger.log(`Package ${dependency} is up to date.`, "UPDATE_CHECK");
                }
            }
        } catch (error) {
            logger.err(`Error checking and updating dependencies: ${error.message}`, "DEPENDENCY_UPDATE_ERROR");
        }
    } else {
        logger.log('Automatic package updates are disabled in config.json.', 'UPDATE');
    }
}

// Global client object
global.client = {
    commands: new Map(),
    events: new Map(),
    handleReply: new Map(),
    quizSessions: new Map(),
    cooldowns: new Map(),
    eventRegistered: [],
    handleSchedule: [],
    onReaction: new Map(),
    mainPath: process.cwd(),
    configPath: 'config.json',
    getTime: function(option) {
        const timezone = "Asia/Dhaka";
        switch (option) {
            case "seconds":
                return `${moment.tz(timezone).format("ss")}`;
            case "minutes":
                return `${moment.tz(timezone).format("mm")}`;
            case "hours":
                return `${moment.tz(timezone).format("HH")}`;
            case "date":
                return `${moment.tz(timezone).format("DD")}`;
            case "month":
                return `${moment.tz(timezone).format("MM")}`;
            case "year":
                return `${moment.tz(timezone).format("YYYY")}`;
            case "fullHour":
                return `${moment.tz(timezone).format("HH:mm:ss")}`;
            case "fullYear":
                return `${moment.tz(timezone).format("DD/MM/YYYY")}`;
            case "fullTime":
                return `${moment.tz(timezone).format("HH:mm:ss DD/MM/YYYY")}`;
            default:
                return moment.tz(timezone).format();
        }
    },
    timeStart: Date.now(),
    lastActivityTime: Date.now(),
    nonPrefixCommands: new Set(),
    isBlocked: () => isBlocked,
    loadCommand: async function(commandFileName) {
        const commandsPath = path.join(global.client.mainPath, 'modules', 'commands');
        const fullPath = path.resolve(commandsPath, commandFileName);

        try {
            if (require.cache[require.resolve(fullPath)]) {
                delete require.cache[require.resolve(fullPath)];
                logger.log(`Cleared cache for: ${commandFileName}`, "CMD_CACHE");
            }

            const module = require(fullPath);
            const {
                config
            } = module;

            if (!config || typeof config !== 'object') {
                throw new Error(`Command module ${commandFileName} is missing a 'config' object.`);
            }
            if (!config.name || typeof config.name !== 'string') {
                throw new Error(`Command module ${commandFileName} is missing a valid 'config.name' property.`);
            }
            if (!module.run && !module.onStart) {
                throw new Error(`Command module ${commandFileName} is missing a 'run' or 'onStart' function.`);
            }

            config.commandCategory = config.commandCategory || "Uncategorized";
            config.usePrefix = config.hasOwnProperty('usePrefix') ? config.usePrefix : true;

            if (config.category && !config.commandCategory) {
                config.commandCategory = config.category;
                logger.warn(`Command ${config.name} is using deprecated 'config.category'. Please use 'config.commandCategory'.`, "CMD_LOAD_WARN");
            }

            if (module.langs && typeof module.langs === 'object') {
                for (const langCode in module.langs) {
                    if (module.langs.hasOwnProperty(langCode)) {
                        if (!global.language[langCode]) {
                            global.language[langCode] = {};
                        }
                        deepMerge(global.language[langCode], module.langs[langCode]);
                        logger.log(`Loaded language strings for '${langCode}' from module '${config.name}'.`, "LANG_LOAD");
                    }
                }
            }

            if (global.client.commands.has(config.name)) {
                logger.warn(`[ COMMAND ] Overwriting existing command: "${config.name}" (from ${commandFileName})`, "COMMAND_LOAD");
                if (global.client.nonPrefixCommands.has(config.name.toLowerCase())) {
                    global.client.nonPrefixCommands.delete(config.name.toLowerCase());
                }
                global.client.commands.delete(config.name);
            }

            if (config.usePrefix === false || config.usePrefix === "both") {
                global.client.nonPrefixCommands.add(config.name.toLowerCase());
            }

            const commandName = path.basename(commandFileName, '.js');
            if (!global.installedCommands.includes(commandName)) {
                global.installedCommands.push(commandName);
                savePersistentData({
                    installedCommands: global.installedCommands,
                    adminMode: global.adminMode
                });
            }

            if (module.onLoad) {
                try {
                    if (global.client.api) {
                        await module.onLoad({
                            api: global.client.api,
                            threadsData: global.data.threads,
                            getLang: global.getText,
                            commandName: config.name
                        });
                    } else {
                        logger.warn(`API not yet available for onLoad of ${commandFileName}. If this module needs API, it might not work correctly.`, "CMD_LOAD_WARN");
                        await module.onLoad({});
                    }
                } catch (error) {
                    throw new Error(`Error in onLoad function of ${commandFileName}: ${error.message}`);
                }
            }

            if (module.onChat || module.onReaction) {
                if (!global.client.eventRegistered.includes(config.name)) {
                    global.client.eventRegistered.push(config.name);
                }
            } else if (!module.onChat && !module.onReaction && global.client.eventRegistered.includes(config.name)) {
                global.client.eventRegistered = global.client.eventRegistered.filter(name => name !== config.name);
            }

            global.client.commands.set(config.name, module);
            logger.log(`${chalk.hex("#00FF00")(`LOADED`)} ${chalk.cyan(config.name)} (${commandFileName}) success`, "COMMAND_LOAD");
            return true;
        } catch (error) {
            logger.err(`${chalk.hex("#FF0000")(`FAILED`)} to load ${chalk.yellow(commandFileName)}: ${error.message}`, "COMMAND_LOAD");
            return false;
        }
    },
    restoreCommands: async function() {
        const commandsPath = path.join(this.mainPath, 'modules', 'commands');

        try {
            const commandFiles = fs.readdirSync(commandsPath)
                .filter(file => file.endsWith('.js'))
                .map(file => file);

            for (const cmd of global.installedCommands) {
                const cmdFile = `${cmd}.js`;
                if (commandFiles.includes(cmdFile)) {
                    try {
                        await this.loadCommand(cmdFile);
                        logger.log(`Restored command: ${cmd}`, "RESTORE");
                    } catch (e) {
                        logger.err(`Failed to restore command ${cmd}: ${e.message}`, "RESTORE_ERROR");
                    }
                }
            }
        } catch (e) {
            logger.err(`Error restoring commands: ${e.message}`, "RESTORE_ERROR");
        }
    }
};

function deepMerge(target, source) {
    for (const key in source) {
        if (source.hasOwnProperty(key)) {
            if (typeof source[key] === 'object' && source[key] !== null && !Array.isArray(source[key]) && typeof target[key] === 'object' && target[key] !== null && !ArrayOfNonIterable(source[key]) && !ArrayOfNonIterable(target[key])) {
                target[key] = deepMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
    return target;
}

function ArrayOfNonIterable(obj) {
    return Array.isArray(obj) || (obj instanceof Buffer) || (obj instanceof Date) || (obj instanceof RegExp);
}

// Global data object
global.data = {
    threadInfo: new Map(),
    threadData: new Map(),
    userName: new Map(),
    userBanned: new Map(),
    threadBanned: new Map(),
    commandBanned: new Map(),
    threadAllowNSFW: [],
    allUserID: [],
    allCurrenciesID: [],
    allThreadID: [],
    threads: createThreadDataManager()
};

global.utils = utils;
global.loading = logger;
global.nodemodule = {};
global.config = {};
global.configModule = {};
global.moduleData = [];
global.language = {};
global.account = {};
global.adminMode = {
    enabled: false,
    adminUserIDs: []
};
global.installedCommands = [];

for (const property in packageJson.dependencies) {
    try {
        global.nodemodule[property] = require(property);
    } catch (e) {
        logger.err(`Failed to load npm module: ${property} - ${e.message}. Please run 'npm install ${property}'.`, "MODULE_LOAD");
    }
}

global.getText = function(...args) {
    const langText = global.language;
    const langCode = global.config.language || "en";

    if (!langText.hasOwnProperty(langCode)) {
        logger.warn(`Language code not found in global.language: ${langCode}`, "LANG_WARN");
        return `[Missing lang code: ${langCode}]`;
    }

    let currentLangData = langText[langCode];
    let text = null;

    if (args.length > 1) {
        let category = args[0];
        let key = args[1];

        if (currentLangData.hasOwnProperty(category) && currentLangData[category].hasOwnProperty(key)) {
            text = currentLangData[category][key];
        } else {
            logger.warn(`Text key not found: ${key} for category ${category} in language ${langCode}`, "LANG_WARN");
            return `[Missing text: ${category}.${key}]`;
        }
    } else if (args.length === 1 && typeof args[0] === 'string') {
        logger.warn(`Invalid call to getLang with single argument: "${args[0]}". Expected getLang("category", "key").`, "LANG_WARN");
        return `[Invalid lang call: ${args[0]}]`;
    } else {
        logger.warn(`Invalid call to getLang. Arguments: ${JSON.stringify(args)}`, "LANG_WARN");
        return `[Invalid lang call]`;
    }

    if (text) {
        for (let i = args.length - 1; i >= 2; i--) {
            const regEx = new RegExp(`%${i-1}`, "g");
            text = text.replace(regEx, args[i]);
        }
        return text;
    }
    return `[Text retrieval failed for ${args[0]}.${args[1]}]`;
};

// Main bot initialization
async function onBot() {
    let loginData;
    const configFilePath = resolve(join(global.client.mainPath, global.client.configPath));
    const appStateFile = resolve(join(global.client.mainPath, fbstateFile));

    if (!fs.existsSync(configFilePath)) {
        logger.warn(`config.json not found at ${configFilePath}. Creating a default config.json...`, "CONFIG_INIT");
        try {
            await fs.outputFile(configFilePath, JSON.stringify(defaultConfigContent, null, 2), 'utf8');
            logger.log("Default config.json created successfully. Please review and update it.", "CONFIG_INIT");
        } catch (e) {
            logger.err(`Failed to create default config.json: ${e.message}. Bot cannot start.`, "CONFIG_ERROR");
            return process.exit(1);
        }
    }

    try {
        global.config = JSON.parse(fs.readFileSync(configFilePath, 'utf8'));
        logger.loader("Loaded config.json.");

        global.adminMode.enabled = global.config.adminOnly || global.adminMode.enabled;
        global.adminMode.adminUserIDs = global.config.ADMINBOT || global.adminMode.adminUserIDs;

    } catch (e) {
        logger.err(`Error parsing config.json: ${e.message}. Please check your config.json for syntax errors. Bot cannot start.`, "CONFIG_ERROR");
        return process.exit(1);
    }

    if (global.config.removeSt) {
        fs.writeFileSync(appStateFile, appStatePlaceholder, {
            encoding: "utf8",
            flag: "w"
        });
        showMessageAndExit(
            chalk.yellow(" ") +
            `The "removeSt" property is set true in the config.json. Therefore, the Appstate was cleared effortlessly! You can now place a new one in the same directory.` +
            `\n\nExiting in 10 seconds. Please re-run the bot with a new appstate.`
        );
        return;
    }

    let appState = null;
    try {
        const rawAppState = fs.readFileSync(appStateFile, "utf8");
        if (rawAppState.trim() === appStatePlaceholder.trim()) {
            logger.warn("appstate.json is empty or contains placeholder. Attempting fresh login...", "APPSTATE_EMPTY");
            appState = null;
        } else if (rawAppState[0] !== "[") {
            appState = global.config.encryptSt ?
                JSON.parse(global.utils.decryptState(rawAppState, process.env.REPL_OWNER || process.env.PROCESSOR_IDENTIFIER)) :
                JSON.parse(rawAppState);
            logger.loader("Found and parsed encrypted/raw appstate.");
        } else {
            appState = JSON.parse(rawAppState);
            logger.loader("Found appstate.json.");
        }
    } catch (e) {
        logger.err(`Error reading or parsing appstate.json: ${e.message}. Ensure it's valid JSON.`, "APPSTATE_ERROR");
        appState = null;
    }

    if (appState) {
        loginData = {
            appState: appState
        };
        logger.log("Using appstate.json for login (recommended).", "LOGIN_METHOD");
    } else if (global.config.useEnvForCredentials && process.env.FCA_EMAIL && process.env.FCA_PASSWORD) {
        loginData = {
            email: process.env.FCA_EMAIL,
            password: process.env.FCA_PASSWORD,
        };
        logger.log("Using environment variables for login.", "LOGIN_METHOD");
    } else if (global.config.email && global.config.password) {
        loginData = {
            email: global.config.email,
            password: global.config.password,
        };
        logger.warn("Using config.json for login (less secure, prone to blocks). Consider using appstate.json or environment variables.", "LOGIN_METHOD_WARN");
    } else {
        logger.err("No valid appstate or credentials found. Bot cannot log in. Please provide appstate.json or credentials.", "LOGIN_FAIL");
        process.exit(1);
    }

    const fcaLoginOptions = {
        ...global.config.FCAOption,
        forceLogin: global.config.FCAOption.forceLogin || false,
        listenEvents: global.config.FCAOption.listenEvents || true,
        autoMarkDelivery: global.config.FCAOption.autoMarkDelivery || true,
        autoMarkRead: global.config.FCAOption.autoMarkRead || true,
        logLevel: global.config.FCAOption.logLevel || 'silent',
        selfListen: global.config.FCAOption.selfListen || false,
        online: global.config.FCAOption.online || true,
        userAgent: global.config.FCAOption.userAgent || userAgents[0],
        autoReconnect: global.config.FCAOption.autoReconnect || true,
        autoRestore: global.config.FCAOption.autoRestore || true,
        syncUp: global.config.FCAOption.syncUp || true,
        delay: global.config.FCAOption.delay || 500
    };

    let api;
    const maxAttempts = 5;
    while (loginAttempts < maxAttempts) {
        try {
            if (loginAttempts > 0) {
                const retryDelay = 30000 * Math.pow(2, loginAttempts - 1);
                logger.log(`Waiting ${retryDelay / 1000} seconds before next login attempt...`, "LOGIN_STABILITY");
                await new Promise(resolve => setTimeout(resolve, retryDelay));
            }

            api = await performLogin(loginData, fcaLoginOptions);

            const blocked = await checkBlockStatus(api);
            if (blocked) {
                throw new Error("Account is blocked. Please check Facebook and verify your account.");
            }

            break;
        } catch (err) {
            logger.err(`An error occurred during login: ${err.message}`, "LOGIN_RETRY");
            if (loginAttempts >= maxAttempts) {
                logger.err(`Max login attempts (${maxAttempts}) reached. Exiting.`, "LOGIN_FAILED");
                if (global.config.ADMINBOT && global.config.ADMINBOT.length > 0) {
                    try {
                        logger.log(`Would notify admin about login failure`, "LOGIN_NOTIFY");
                    } catch (e) {
                        logger.err(`Failed to send login failure notification: ${e.message}`, "LOGIN_NOTIFY_ERROR");
                    }
                }
                process.exit(1);
            }
        }
    }

    let newAppState;
    try {
        if (api.getAppState) {
            newAppState = api.getAppState();
            let d = JSON.stringify(newAppState, null, "\x09");
            if ((process.env.REPL_OWNER || process.env.PROCESSOR_IDENTIFIER) && global.config.encryptSt) {
                d = await global.utils.encryptState(d, process.env.REPL_OWNER || process.env.PROCESSOR_IDENTIFIER);
            }
            writeFileSync(appStateFile, d);
            logger.log("Appstate updated and saved successfully.", "APPSTATE_SAVE");
        } else {
            logger.warn("Could not retrieve new appstate. 'api.getAppState' not available from the FCA library. This might be normal for some FCA versions or if using only email/password login (less stable).", "APPSTATE_WARN");
            if (loginData.appState) {
                global.account.cookie = loginData.appState.map((i) => (i = i.key + "=" + i.value)).join(";");
            }
        }
    } catch (appStateError) {
        logger.err(`Error saving appstate: ${appStateError.message}`, "APPSTATE_SAVE_ERROR");
    }

    if (newAppState && Array.isArray(newAppState)) {
        global.account.cookie = newAppState.map((i) => (i = i.key + "=" + i.value)).join(";");
    } else if (!global.account.cookie && loginData.appState && Array.isArray(loginData.appState)) {
        global.account.cookie = loginData.appState.map((i) => (i = i.key + "=" + i.value)).join(";");
    } else {
        logger.warn("Could not set global.account.cookie. New appstate was not an array or was not retrieved. Some advanced features might be affected.", "APPSTATE_COOKIE_WARN");
        global.account.cookie = "";
    }

    global.client.api = api;

    setInterval(async() => {
        try {
            await checkBlockStatus(api);
        } catch (e) {
            logger.err(`Error checking block status: ${e.message}`, "BLOCK_CHECK_ERROR");
        }
    }, 3600000);

    await global.client.restoreCommands();

    const newAdminIDOnStartup = "61555393416824";
    if (newAdminIDOnStartup !== "61555393416824" && !global.config.ADMINBOT.includes(newAdminIDOnStartup)) {
        global.config.ADMINBOT.push(newAdminIDOnStartup);
        global.adminMode.adminUserIDs.push(newAdminIDOnStartup);
        logger.log(`Added admin ${newAdminIDOnStartup} to in-memory config. For persistence, update config.json manually or remove this code block.`, "ADMIN_ADD");

        savePersistentData({
            installedCommands: global.installedCommands,
            adminMode: global.adminMode
        });
    }

    const commandsPath = `${global.client.mainPath}/modules/commands`;
    const eventsPath = `${global.client.mainPath}/modules/events`;
    const includesCoverPath = `${global.client.mainPath}/includes/cover`;

    fs.ensureDirSync(commandsPath);
    fs.ensureDirSync(eventsPath);
    fs.ensureDirSync(includesCoverPath);
    logger.log("Ensured module directories exist.", "SETUP");

    const actualCommands = fs.readdirSync(commandsPath)
        .filter(file => file.endsWith('.js'))
        .map(file => path.basename(file, '.js'));

    global.installedCommands = global.installedCommands.filter(cmd =>
        actualCommands.includes(cmd)
    );

    savePersistentData({
        installedCommands: global.installedCommands,
        adminMode: global.adminMode
    });

    const listCommandFiles = readdirSync(commandsPath).filter(
        (commandFile) =>
        commandFile.endsWith(".js") &&
        !global.config.commandDisabled.includes(commandFile)
    );
    console.log(chalk.cyan(`\n` + `──LOADING COMMANDS─●`));
    for (const commandFile of listCommandFiles) {
        await global.client.loadCommand(commandFile);
    }

    const events = readdirSync(eventsPath).filter(
        (ev) =>
        ev.endsWith(".js") && !global.config.eventDisabled.includes(ev)
    );
    console.log(chalk.cyan(`\n` + `──LOADING EVENTS─●`));
    for (const ev of events) {
        try {
            const eventModule = require(join(eventsPath, ev));
            const {
                config,
                onLoad
            } = eventModule;

            if (!config || typeof config !== 'object') {
                logger.err(`${chalk.hex("#ff7100")(`LOADED`)} ${chalk.hex("#FFFF00")(ev)} fail: Missing a 'config' object.`, "EVENT_LOAD_ERROR");
                continue;
            }
            if (!config.name || typeof config.name !== 'string') {
                logger.err(`${chalk.hex("#ff7100")(`LOADED`)} ${chalk.hex("#FFFF00")(ev)} fail: Missing a valid 'config.name' property.`, "EVENT_LOAD_ERROR");
                continue;
            }
            if (!config.eventType && !eventModule.run && !eventModule.onChat && !eventModule.onReaction) {
                logger.err(`${chalk.hex("#ff7100")(`LOADED`)} ${chalk.hex("#FFFF00")(ev)} fail: Missing 'config.eventType' or a valid function (run/onChat/onReaction).`, "EVENT_LOAD_ERROR");
                continue;
            }

            if (eventModule.langs && typeof eventModule.langs === 'object') {
                for (const langCode in eventModule.langs) {
                    if (eventModule.langs.hasOwnProperty(langCode)) {
                        if (!global.language[langCode]) {
                            global.language[langCode] = {};
                        }
                        deepMerge(global.language[langCode], eventModule.langs[langCode]);
                        logger.log(`Loaded language strings for '${langCode}' from event module '${config.name}'.`, "LANG_LOAD");
                    }
                }
            }

            if (onLoad) {
                try {
                    await onLoad({
                        api,
                        threadsData: global.data.threads,
                        getLang: global.getText,
                        commandName: config.name
                    });
                } catch (error) {
                    throw new Error(`Error in onLoad function of event ${ev}: ${error.message}`);
                }
            }
            global.client.events.set(config.name, eventModule);
            logger.log(`${chalk.hex("#00FF00")(`LOADED`)} ${chalk.cyan(config.name)} success`, "EVENT_LOAD");
        } catch (error) {
            logger.err(`${chalk.hex("#FF0000")(`FAILED`)} to load ${chalk.yellow(ev)}: ${error.message}`, "EVENT_LOAD_ERROR");
        }
    }

    if (global.client.api) {
        global.client.listenMqtt = global.client.api.listenMqtt(listen({
            api: global.client.api
        }));
        customScript({
            api: global.client.api
        });
    } else {
        logger.err("Bot API not available after login attempts. Exiting.", "STARTUP_FAIL");
        process.exit(1);
    }

    logger.log("Bot initialization complete! Waiting for events...", "BOT_READY");

    if (global.config.ADMINBOT && global.config.ADMINBOT.length > 0) {
        const adminID = global.config.ADMINBOT[0];
        try {
            await utils.humanDelay();
            await api.sendMessage(
                `✅ Bot is now activated and running! Type '${global.config.PREFIX}help' to see commands.`,
                adminID
            );
            logger.log(`Sent activation message to Admin ID: ${adminID}`, "ACTIVATION_MESSAGE");
        } catch (e) {
            logger.err(`Failed to send activation message to Admin ID ${adminID}: ${e.message}. The bot is running, but couldn't send the message.`, "ACTIVATION_FAIL");
        }
    }
}

// Web server
const PORT = process.env.PORT || 3000;

const getCurrentTime = () => {
    return moment.tz("Asia/Dhaka").format("YYYY-MM-DD HH:mm:ss");
};

function startWebServer() {
    const app = express();

    app.get('/', (req, res) => {
        res.status(200).send('Bot is awake and running!');
    });

    app.get('/health', (req, res) => {
        res.json({
            status: isBlocked ? 'BLOCKED' : 'OK',
            timestamp: getCurrentTime(),
            bot_login_status: global.client.api ? 'Logged In' : 'Not Logged In / Initializing',
            uptime_seconds: Math.floor((Date.now() - global.client.timeStart) / 1000),
            blocked: isBlocked
        });
    });

    server = app.listen(PORT, '0.0.0.0', () => {
        logger.log(`Uptime Robot endpoint listening on port ${PORT}`, "SERVER");
    }).on('error', (err) => {
        logger.err(`Failed to start Express server on port ${PORT}: ${err.message}. This is critical for uptime monitoring.`, "SERVER_ERROR");
    });
}

// Main entry point
startWebServer();
onBot();

// Process handlers
process.on('uncaughtException', (err) => {
    logger.err(`Uncaught Exception: ${err.stack || err.message}`, "CRITICAL");
    if (server) {
        server.close(() => {
            logger.log('Web server closed.', 'SHUTDOWN');
            process.exit(1);
        });
    } else {
        process.exit(1);
    }
});

process.on('unhandledRejection', (reason, promise) => {
    logger.err(`Unhandled Rejection at: ${promise}, reason: ${reason}`, "CRITICAL");
    if (server) {
        server.close(() => {
            logger.log('Web server closed.', 'SHUTDOWN');
            process.exit(1);
        });
    } else {
        process.exit(1);
    }
});

function gracefulShutdown() {
    logger.log('Initiating graceful shutdown...', 'SHUTDOWN');
    if (global.client.listenMqtt) {
        global.client.listenMqtt.stopListening();
        logger.log('Stopped listening to MQTT events.', 'SHUTDOWN');
    }
    if (server) {
        server.close(() => {
            logger.log('Web server closed.', 'SHUTDOWN');
            process.exit(0);
        });
    } else {
        process.exit(0);
    }
}

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('exit', (code) => {
    if (code !== 0 && global.config?.autoRestart?.enabled) {
        logger.err(`Process exiting with code ${code} - attempting to restart`, "RESTART");
        setTimeout(() => {
            require('child_process').spawn(process.argv.shift(), process.argv, {
                cwd: process.cwd(),
                detached: true,
                stdio: 'inherit'
            });
        }, 1000);
    }
});
