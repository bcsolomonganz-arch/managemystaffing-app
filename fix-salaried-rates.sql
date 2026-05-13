-- Fix salaried employees: convert weekly pay to effective hourly rate
-- Generated 2026-05-13T02:23:12.669Z
BEGIN;

-- Abell, Keelan (Plainview Healthcare Center): $1600/wk / 40h = $40/hr ($83200/yr)
UPDATE employees SET hourly_rate = 40 WHERE id = 'e_p200229';
-- Acosta, Araseli (Lakeside Rehab and Care Center): $1360/wk / 40h = $34/hr ($70720/yr)
UPDATE employees SET hourly_rate = 34 WHERE id = 'e_p250618';
-- Aguirre, Erica L (Kirkland Court): $1533.85/wk / 40h = $38.35/hr ($79760.2/yr)
UPDATE employees SET hourly_rate = 38.35 WHERE id = 'e_p120010';
-- Anzaldua, Brenda H (Levelland Nursing and Rehab Center): $1080/wk / 40h = $27/hr ($56160/yr)
UPDATE employees SET hourly_rate = 27 WHERE id = 'e_p140101';
-- Ascencio, Claudia (Plainview Healthcare Center): $869.11/wk / 40h = $21.73/hr ($45193.72/yr)
UPDATE employees SET hourly_rate = 21.73 WHERE id = 'e_p200055';
-- Austin, Tina (Warr Acres): $1769.2/wk / 40h = $44.23/hr ($91998.4/yr)
UPDATE employees SET hourly_rate = 44.23 WHERE id = 'e_p280002';
-- Baah, Richard (Lodge at Brookline): $2500/wk / 40h = $62.5/hr ($130000/yr)
UPDATE employees SET hourly_rate = 62.5 WHERE id = 'e_p260121';
-- Barnes, Merce (Pampa Nursing Center): $916.68/wk / 40h = $22.92/hr ($47667.36/yr)
UPDATE employees SET hourly_rate = 22.92 WHERE id = 'e_p210046';
-- Blevins, Jana Michelle (Heartsworth Center Nursing and Rehab): $2080/wk / 40h = $52/hr ($108160/yr)
UPDATE employees SET hourly_rate = 52 WHERE id = 'e_p360386';
-- Briner, Matthew (Warr Acres): $1240/wk / 40h = $31/hr ($64480/yr)
UPDATE employees SET hourly_rate = 31 WHERE id = 'e_p280005';
-- Brown, Janet (Plainview Healthcare Center): $1919.36/wk / 40h = $47.98/hr ($99806.72/yr)
UPDATE employees SET hourly_rate = 47.98 WHERE id = 'e_p200478';
-- Brown, Mayra (OMCI): $740/wk / 40h = $18.5/hr ($38480/yr)
UPDATE employees SET hourly_rate = 18.5 WHERE id = 'e_p270056';
-- Bruner, Jennifer N (Pampa Nursing Center): $1923.08/wk / 40h = $48.08/hr ($100000.16/yr)
UPDATE employees SET hourly_rate = 48.08 WHERE id = 'e_p210115';
-- Bryan, Ashley (Beacon Ridge Senior Mental Health): $961.54/wk / 40h = $24.04/hr ($50000.08/yr)
UPDATE employees SET hourly_rate = 24.04 WHERE id = 'e_p180989';
-- Carrillo, Misti (Plainview Healthcare Center): $1010/wk / 40h = $25.25/hr ($52520/yr)
UPDATE employees SET hourly_rate = 25.25 WHERE id = 'e_p200170';
-- Cerda, Daisy (Plainview Healthcare Center): $1826.93/wk / 40h = $45.67/hr ($95000.36/yr)
UPDATE employees SET hourly_rate = 45.67 WHERE id = 'e_p200038';
-- Clay, Sonya E (Cross Timbers Senior Mental Health): $1875/wk / 40h = $46.88/hr ($97500/yr)
UPDATE employees SET hourly_rate = 46.88 WHERE id = 'e_p170672';
-- Combest, Krista (OMCI): $1600/wk / 40h = $40/hr ($83200/yr)
UPDATE employees SET hourly_rate = 40 WHERE id = 'e_p270007';
-- Cornwell, Crystal (Lodge at Brookline): $1826.8/wk / 40h = $45.67/hr ($94993.6/yr)
UPDATE employees SET hourly_rate = 45.67 WHERE id = 'e_p260007';
-- Crawford, Braden G (Heartsworth Center Nursing and Rehab): $1576.92/wk / 40h = $39.42/hr ($81999.84/yr)
UPDATE employees SET hourly_rate = 39.42 WHERE id = 'e_p360388';
-- Darrow, Joanna L (Colonial Manor): $1680/wk / 40h = $42/hr ($87360/yr)
UPDATE employees SET hourly_rate = 42 WHERE id = 'e_p220059';
-- Diaz, Anna (Windsor Hills): $2403.85/wk / 40h = $60.1/hr ($125000.2/yr)
UPDATE employees SET hourly_rate = 60.1 WHERE id = 'e_p290010';
-- Donley, Dinah (North County Assisted Living): $2115.38/wk / 40h = $52.88/hr ($109999.76/yr)
UPDATE employees SET hourly_rate = 52.88 WHERE id = 'e_p350055';
-- Dreadfulwater, Dusty Lyne (Heartsworth Center Nursing and Rehab): $1634.4/wk / 40h = $40.86/hr ($84988.8/yr)
UPDATE employees SET hourly_rate = 40.86 WHERE id = 'e_p360029';
-- Ellerd, Jim T (Levelland Nursing and Rehab Center): $1910.43/wk / 40h = $47.76/hr ($99342.36/yr)
UPDATE employees SET hourly_rate = 47.76 WHERE id = 'e_p140018';
-- Ferrell, Paige (Franciscan Villa): $1644.25/wk / 40h = $41.11/hr ($85501/yr)
UPDATE employees SET hourly_rate = 41.11 WHERE id = 'e_p240195';
-- Hammit, Ronna (Pampa Nursing Center): $1770.84/wk / 40h = $44.27/hr ($92083.68/yr)
UPDATE employees SET hourly_rate = 44.27 WHERE id = 'e_p210052';
-- Hayes, April (Heartsworth Center Nursing and Rehab): $2115.2/wk / 40h = $52.88/hr ($109990.4/yr)
UPDATE employees SET hourly_rate = 52.88 WHERE id = 'e_p360051';
-- Hill, Kristi D (Levelland Nursing and Rehab Center): $2019.23/wk / 40h = $50.48/hr ($104999.96/yr)
UPDATE employees SET hourly_rate = 50.48 WHERE id = 'e_p140181';
-- Hilton, Shelly (Arbor Village Nursing and Rehabilitation): $1846.15/wk / 40h = $46.15/hr ($95999.8/yr)
UPDATE employees SET hourly_rate = 46.15 WHERE id = 'e_p150392';
-- Hoganson, Holly R (Pampa Nursing Center): $1854.74/wk / 40h = $46.37/hr ($96446.48/yr)
UPDATE employees SET hourly_rate = 46.37 WHERE id = 'e_p210022';
-- Holman, Cleo (Warr Acres): $844/wk / 40h = $21.1/hr ($43888/yr)
UPDATE employees SET hourly_rate = 21.1 WHERE id = 'e_p280027';
-- Hyslop, Lydia (North County Nursing and Rehab): $1600/wk / 40h = $40/hr ($83200/yr)
UPDATE employees SET hourly_rate = 40 WHERE id = 'e_p340253';
-- Kallmeyer, Summer (OMCI): $1826.92/wk / 40h = $45.67/hr ($94999.84/yr)
UPDATE employees SET hourly_rate = 45.67 WHERE id = 'e_p270123';
-- Landis, Jeanette (Windsor Hills): $1730.77/wk / 40h = $43.27/hr ($90000.04/yr)
UPDATE employees SET hourly_rate = 43.27 WHERE id = 'e_p290097';
-- Lott, Tonya (Lodge at Brookline): $960/wk / 40h = $24/hr ($49920/yr)
UPDATE employees SET hourly_rate = 24 WHERE id = 'e_p260039';
-- Marshall, Andrea (Arbor Village Nursing and Rehabilitation): $1826.92/wk / 40h = $45.67/hr ($94999.84/yr)
UPDATE employees SET hourly_rate = 45.67 WHERE id = 'e_p150364';
-- May, Stephanie C (Cross Timbers Senior Mental Health): $1354.17/wk / 40h = $33.85/hr ($70416.84/yr)
UPDATE employees SET hourly_rate = 33.85 WHERE id = 'e_p170060';
-- McDaniel, Kristy (Lakeside Rehab and Care Center): $1730.77/wk / 40h = $43.27/hr ($90000.04/yr)
UPDATE employees SET hourly_rate = 43.27 WHERE id = 'e_p250290';
-- McNamara, Danielle (North County Nursing and Rehab): $2115.39/wk / 40h = $52.88/hr ($110000.28/yr)
UPDATE employees SET hourly_rate = 52.88 WHERE id = 'e_p340316';
-- Michaels, Victoria J (Cross Timbers Senior Mental Health): $1720/wk / 40h = $43/hr ($89440/yr)
UPDATE employees SET hourly_rate = 43 WHERE id = 'e_p170619';
-- Mills, Tanya D (Kirkland Court): $2259.62/wk / 40h = $56.49/hr ($117500.24/yr)
UPDATE employees SET hourly_rate = 56.49 WHERE id = 'e_p120365';
-- Montgomery, Shellie R (Cross Timbers Senior Mental Health): $1730.77/wk / 40h = $43.27/hr ($90000.04/yr)
UPDATE employees SET hourly_rate = 43.27 WHERE id = 'e_p170638';
-- Moye, Marteka (Bell Avenue Nursing Center): $1442.31/wk / 40h = $36.06/hr ($75000.12/yr)
UPDATE employees SET hourly_rate = 36.06 WHERE id = 'e_p160262';
-- Mullins, Terri (Colonial Manor): $2115.2/wk / 40h = $52.88/hr ($109990.4/yr)
UPDATE employees SET hourly_rate = 52.88 WHERE id = 'e_p220028';
-- Munn, Marleka K (Lodge at Brookline): $1720/wk / 40h = $43/hr ($89440/yr)
UPDATE employees SET hourly_rate = 43 WHERE id = 'e_p260074';
-- Nicholson, Melissa (Kirkland Court): $1680/wk / 40h = $42/hr ($87360/yr)
UPDATE employees SET hourly_rate = 42 WHERE id = 'e_p120046';
-- Oduola, Deen (Windsor Hills): $1732.4/wk / 40h = $43.31/hr ($90084.8/yr)
UPDATE employees SET hourly_rate = 43.31 WHERE id = 'e_p290043';
-- ONeal, Julie (Lakeside Rehab and Care Center): $1115.38/wk / 40h = $27.88/hr ($57999.76/yr)
UPDATE employees SET hourly_rate = 27.88 WHERE id = 'e_p250593';
-- Ovalle, Laurie (Crosbyton Nursing and Rehab): $1120/wk / 40h = $28/hr ($58240/yr)
UPDATE employees SET hourly_rate = 28 WHERE id = 'e_p000116';
-- Perez, Aimee (Plainview Healthcare Center): $1634.62/wk / 40h = $40.87/hr ($85000.24/yr)
UPDATE employees SET hourly_rate = 40.87 WHERE id = 'e_p200050';
-- Petroski, Jennifer L (Pampa Nursing Center): $1516.67/wk / 40h = $37.92/hr ($78866.84/yr)
UPDATE employees SET hourly_rate = 37.92 WHERE id = 'e_p210031';
-- Rife, Michael (OMCI): $2307.6/wk / 40h = $57.69/hr ($119995.2/yr)
UPDATE employees SET hourly_rate = 57.69 WHERE id = 'e_p270047';
-- Rivas, Gerald G (Levelland Nursing and Rehab Center): $1329.23/wk / 40h = $33.23/hr ($69119.96/yr)
UPDATE employees SET hourly_rate = 33.23 WHERE id = 'e_p140212';
-- Robbins, Brittainy (Kirkland Court): $2211.54/wk / 40h = $55.29/hr ($115000.08/yr)
UPDATE employees SET hourly_rate = 55.29 WHERE id = 'e_p120389';
-- Rodgers, Savanna D (Bell Avenue Nursing Center): $960/wk / 40h = $24/hr ($49920/yr)
UPDATE employees SET hourly_rate = 24 WHERE id = 'e_p160071';
-- Rowe, Terri (Warr Acres): $2307.6/wk / 40h = $57.69/hr ($119995.2/yr)
UPDATE employees SET hourly_rate = 57.69 WHERE id = 'e_p280051';
-- Sagely, Laurie (Franciscan Villa): $1240/wk / 40h = $31/hr ($64480/yr)
UPDATE employees SET hourly_rate = 31 WHERE id = 'e_p240094';
-- Saucedo, Diana Molina (Crosbyton Nursing and Rehab): $1538.46/wk / 40h = $38.46/hr ($79999.92/yr)
UPDATE employees SET hourly_rate = 38.46 WHERE id = 'e_p000214';
-- Scholz, Clinton (Arbor Village Nursing and Rehabilitation): $2080/wk / 40h = $52/hr ($108160/yr)
UPDATE employees SET hourly_rate = 52 WHERE id = 'e_p150345';
-- Scullawl, Shelly R (Franciscan Villa): $2192.31/wk / 40h = $54.81/hr ($114000.12/yr)
UPDATE employees SET hourly_rate = 54.81 WHERE id = 'e_p240134';
-- Shelton, Eisen (North County Nursing and Rehab): $1923.08/wk / 40h = $48.08/hr ($100000.16/yr)
UPDATE employees SET hourly_rate = 48.08 WHERE id = 'e_p340260';
-- Simmons, Michelle (Windsor Hills): $1098.4/wk / 40h = $27.46/hr ($57116.8/yr)
UPDATE employees SET hourly_rate = 27.46 WHERE id = 'e_p290052';
-- Sprague, Michele (Franciscan Villa): $2708.33/wk / 40h = $67.71/hr ($140833.16/yr)
UPDATE employees SET hourly_rate = 67.71 WHERE id = 'e_p240261';
-- Taylor, Corley Alyse (Levelland Nursing and Rehab Center): $2211.54/wk / 40h = $55.29/hr ($115000.08/yr)
UPDATE employees SET hourly_rate = 55.29 WHERE id = 'e_p140163';
-- Thiessen, Trever D (Bell Avenue Nursing Center): $1730.77/wk / 40h = $43.27/hr ($90000.04/yr)
UPDATE employees SET hourly_rate = 43.27 WHERE id = 'e_p160052';
-- Thornhill, Elizabeth (Colonial Manor): $1769.2/wk / 40h = $44.23/hr ($91998.4/yr)
UPDATE employees SET hourly_rate = 44.23 WHERE id = 'e_p220047';
-- Tiner, Vivian (Crosbyton Nursing and Rehab): $1384.8/wk / 40h = $34.62/hr ($72009.6/yr)
UPDATE employees SET hourly_rate = 34.62 WHERE id = 'e_p000053';
-- Tipton, Sherry Ann (Heartsworth Center Nursing and Rehab): $1520/wk / 40h = $38/hr ($79040/yr)
UPDATE employees SET hourly_rate = 38 WHERE id = 'e_p360122';
-- Turner, Forrest (Lakeside Rehab and Care Center): $2067.31/wk / 40h = $51.68/hr ($107500.12/yr)
UPDATE employees SET hourly_rate = 51.68 WHERE id = 'e_p250624';
-- Villa, Roberta (Beacon Ridge Senior Mental Health): $1788.46/wk / 40h = $44.71/hr ($92999.92/yr)
UPDATE employees SET hourly_rate = 44.71 WHERE id = 'e_p180905';
-- Villarreal, George (Crosbyton Nursing and Rehab): $1250/wk / 40h = $31.25/hr ($65000/yr)
UPDATE employees SET hourly_rate = 31.25 WHERE id = 'e_p000118';
-- Villarreal, Veronica Salazar (Lakeside Rehab and Care Center): $1080/wk / 40h = $27/hr ($56160/yr)
UPDATE employees SET hourly_rate = 27 WHERE id = 'e_p250291';
-- Whitaker, Lacie (Windsor Hills): $1800/wk / 40h = $45/hr ($93600/yr)
UPDATE employees SET hourly_rate = 45 WHERE id = 'e_p290064';
-- Wood, Joanna (Bell Avenue Nursing Center): $1720/wk / 40h = $43/hr ($89440/yr)
UPDATE employees SET hourly_rate = 43 WHERE id = 'e_p160292';
-- Zamora, Michael (Kirkland Court): $1442.31/wk / 40h = $36.06/hr ($75000.12/yr)
UPDATE employees SET hourly_rate = 36.06 WHERE id = 'e_p120338';

COMMIT;

-- 76 salaried employees corrected