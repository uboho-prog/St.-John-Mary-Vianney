import Database from "better-sqlite3";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const db = new Database(path.resolve(__dirname, "donations.db"));

db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
  CREATE TABLE IF NOT EXISTS donations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    amount INTEGER NOT NULL,
    reference TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'success',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )
`);

export interface Donation {
  email: string;
  amount: number;
  reference: string;
  status: string;
}

const insertDonation = db.prepare(
  `INSERT OR IGNORE INTO donations (email, amount, reference, status) VALUES (@email, @amount, @reference, @status)`
);

export function saveDonation(donation: Donation): boolean {
  const result = insertDonation.run(donation);
  return result.changes > 0;
}

export interface DonationRow extends Donation {
  id: number;
  created_at: string;
}

export function getAllDonations(sortBy: string, sortDir: string): DonationRow[] {
  const allowedSorts: Record<string, string> = {
    created_at: "created_at",
    amount: "amount",
  };
  const column = allowedSorts[sortBy] || "created_at";
  const dir = sortDir === "asc" ? "ASC" : "DESC";

  const stmt = db.prepare(`SELECT * FROM donations ORDER BY ${column} ${dir}`);
  return stmt.all() as DonationRow[];
}
