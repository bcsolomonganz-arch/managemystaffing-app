#!/usr/bin/env node
/**
 * One-time migration script: Provision Twilio SMS numbers for all active
 * buildings that don't already have one. Works directly against the data
 * file and Twilio API (bypasses the server's fully-set-up gate).
 *
 * Usage:  node scripts/provision-all-buildings.js
 */
require('dotenv').config({ path: 'C:/ProgramData/ManageMyStaffing/.env' });
const fs = require('fs'), crypto = require('crypto');

const DATA_FILE = process.env.DATA_FILE;
const KEY = process.env.DATA_ENCRYPTION_KEY;
const APP_URL = process.env.APP_URL || 'https://managemystaffing.com';

// ZIP-to-area-code lookup (mirrors server.js)
const _ZIP3_TO_AREA = {
  '730':'405','731':'405','732':'405','734':'405','735':'405','736':'580','737':'580','738':'580','739':'580',
  '740':'918','741':'918','743':'918','744':'918','745':'918','746':'918','747':'918','748':'580','749':'918',
  '750':'214','751':'214','752':'214','753':'214','754':'214','755':'903','756':'430','757':'409','758':'409','759':'936',
  '760':'682','761':'817','762':'817','763':'940','764':'940','766':'806','767':'325','768':'325','769':'432',
  '770':'713','772':'713','773':'713','774':'713','775':'409','776':'936','777':'409','778':'979','779':'254',
  '780':'512','781':'737','785':'956','786':'956','787':'512','788':'210','789':'830',
  '790':'806','791':'806','792':'806','793':'915','794':'915','795':'325','796':'432','797':'432','798':'915','799':'915',
  '500':'515','501':'515','502':'515','503':'641','504':'641','505':'641','506':'515','507':'515','508':'515',
  '510':'712','511':'712','512':'712','513':'712','514':'712','515':'712','516':'712','520':'515','521':'319',
  '522':'319','523':'319','524':'319','525':'319','526':'319','527':'563','528':'563',
  '350':'205','351':'205','352':'205','354':'205','355':'205','356':'205','357':'205','358':'205','359':'334','360':'334',
  '361':'334','362':'251','363':'251','364':'251','365':'251','366':'251','367':'334','368':'334','369':'334',
  '100':'212','101':'212','102':'212','103':'212','110':'516','111':'212','112':'718',
  '600':'773','601':'773','602':'847','603':'773','604':'773',
  '900':'213','902':'310','903':'310','904':'310','905':'310','906':'562','907':'562','908':'562','910':'818','913':'818','917':'310','918':'714','919':'714','920':'760','921':'760',
};
function zipToAreaCode(zip) {
  if (!zip) return null;
  return _ZIP3_TO_AREA[String(zip).trim().slice(0, 3)] || null;
}

// Oklahoma ZIP-to-area-code (broader coverage for OK ZIPs not in the main table)
const OK_ZIP_AREA = {
  '730':'405','731':'405','734':'405','735':'405',
  '736':'580','737':'580','738':'580','739':'580',
  '740':'918','741':'918','743':'918','744':'918','745':'918','746':'918','747':'918','748':'580','749':'918',
};
function zipToAreaCodeExtended(zip) {
  const base = zipToAreaCode(zip);
  if (base) return base;
  if (!zip) return null;
  const z3 = String(zip).trim().slice(0, 3);
  // Oklahoma ZIPs: 730-749
  if (z3 >= '730' && z3 <= '749') return OK_ZIP_AREA[z3] || '405';
  // Texas ZIPs: 750-799
  if (z3 >= '750' && z3 <= '799') return '806';
  return null;
}

async function main() {
  // Decrypt data
  const raw = fs.readFileSync(DATA_FILE, 'utf8');
  const p = JSON.parse(raw);
  const iv = Buffer.from(p.iv, 'hex'), tag = Buffer.from(p.authTag, 'hex');
  const d = crypto.createDecipheriv('aes-256-gcm', Buffer.from(KEY, 'hex'), iv);
  d.setAuthTag(tag);
  const dec = Buffer.concat([d.update(Buffer.from(p.data, 'hex')), d.final()]);
  const data = JSON.parse(dec.toString());

  // Init Twilio
  const twilio = require('twilio')(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  const smsWebhookUrl = `${APP_URL}/api/sms/inbound`;

  const buildings = data.buildings.filter(b => !b.inactive);
  console.log(`Found ${buildings.length} active buildings.\n`);

  let provisioned = 0, skipped = 0, failed = 0;

  for (const b of buildings) {
    if (b.smsFromPhone && b.smsProvisionStatus === 'active') {
      console.log(`  SKIP     ${b.name} — already has ${b.smsFromPhone}`);
      skipped++;
      continue;
    }

    const areaCode = zipToAreaCodeExtended(b.zip);
    if (!areaCode) {
      console.log(`  NO-AREA  ${b.name} — ZIP ${b.zip} has no area code mapping`);
      failed++;
      continue;
    }

    try {
      // Search for available local number
      const available = await twilio.availablePhoneNumbers('US').local.list({
        areaCode,
        smsEnabled: true,
        limit: 1,
      });
      if (!available.length) {
        console.log(`  NO-NUM   ${b.name} — no numbers in area code ${areaCode}`);
        failed++;
        continue;
      }

      // Purchase and configure webhook
      const purchased = await twilio.incomingPhoneNumbers.create({
        phoneNumber: available[0].phoneNumber,
        smsUrl: smsWebhookUrl,
        smsMethod: 'POST',
      });

      b.smsFromPhone = purchased.phoneNumber;
      b.smsFromPhoneSid = purchased.sid;
      b.smsProvisionStatus = 'active';
      b.smsProvisionedAt = new Date().toISOString();
      b.smsCostUsd = 1.15;
      console.log(`  OK       ${b.name} → ${purchased.phoneNumber} (${areaCode})`);
      provisioned++;
    } catch (e) {
      b.smsProvisionStatus = 'failed';
      b.smsProvisionError = e.message?.slice(0, 200) || 'unknown';
      console.log(`  ERROR    ${b.name} — ${e.message}`);
      failed++;
    }

    // Pause between purchases to respect rate limits
    await new Promise(r => setTimeout(r, 1500));
  }

  // Re-encrypt and save
  const newIv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', Buffer.from(KEY, 'hex'), newIv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()]);
  const authTag = cipher.getAuthTag();
  fs.writeFileSync(DATA_FILE, JSON.stringify({
    iv: newIv.toString('hex'),
    data: encrypted.toString('hex'),
    authTag: authTag.toString('hex'),
  }));

  console.log(`\nData saved. ${provisioned} provisioned, ${skipped} already had numbers, ${failed} failed.`);
}

main().catch(e => { console.error(e); process.exit(1); });
