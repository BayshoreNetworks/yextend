-- Creating a table
CREATE TABLE fyi_links (id INTEGER PRIMARY KEY,
  url VARCHAR(16) NOT NULL,
  notes VARCHAR(16),
  counts INTEGER,
  created TIMESTAMP DEFAULT CURRENT_TIMESTAMP());
     
-- Inserting a row
INSERT INTO fyi_links VALUES (101, 
  'dev.fyicenter.com', 
  NULL,
  0,
  '2006-04-30');
  
-- Retrieving data
SELECT * FROM fyi_links ORDER BY created DESC;  