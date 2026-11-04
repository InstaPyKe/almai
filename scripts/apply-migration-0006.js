import fs from 'node:fs';
import path from 'node:path';
import { DatabaseSync } from 'node:sqlite';

function findDbs(dir) {
  let results = [];
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, item.name);
    if (item.isDirectory()) {
      results = results.concat(findDbs(full));
    } else if (item.name.endsWith('.sqlite')) {
      results.push(full);
    }
  }
  return results;
}

const rawSql = fs.readFileSync('migrations/0006_package_withdrawal_limits_and_referral_balance.sql', 'utf8');
// Clean comments line by line
const cleanedSql = rawSql
  .split('\n')
  .map(line => {
    const trimmed = line.trim();
    return trimmed.startsWith('--') ? '' : line;
  })
  .join('\n');

const statements = cleanedSql
  .split(';')
  .map(s => s.trim())
  .filter(s => s.length > 0);

console.log('Statements to execute:', statements.length);

const dbs = findDbs('.wrangler');
for (const dbPath of dbs) {
  try {
    const db = new DatabaseSync(dbPath);
    const hasPackages = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='packages'").get();
    if (!hasPackages) continue;

    console.log('Migrating:', dbPath);
    for (const stmt of statements) {
      try {
        db.exec(stmt);
      } catch (err) {
        if (!err.message.includes('duplicate column name')) {
          console.warn('Stmt warning:', err.message, 'on stmt:', stmt);
        }
      }
    }
    const pkgs = db.prepare('SELECT id, name, price_ksh, min_withdrawal_views_ksh FROM packages').all();
    console.log('Migrated packages in ' + path.basename(dbPath) + ':', pkgs);
    const walletCols = db.prepare('PRAGMA table_info(wallets)').all().map(c => c.name);
    console.log('Wallet columns:', walletCols);
  } catch (err) {
    console.error(dbPath, 'error:', err.message);
  }
}
console.log('Migration 0006 successfully applied.');
