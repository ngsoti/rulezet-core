/**
 * starfield-game.js — tiny vanilla-JS 2D space survival game.
 * No dependencies, no external assets. All audio (sound effects AND the
 * background music) is generated live via the Web Audio API — there are
 * no audio files anywhere, so there's nothing to license.
 *
 * 5 levels of increasing difficulty (more asteroids, then alien chasers
 * that shoot back) ending in a boss fight. Ship skins are just palettes
 * applied to the same vector-drawn ship — no sprite assets needed.
 *
 * Controls: Arrow keys / WASD to fly, Space to fire, P / Esc to pause.
 */
(function () {
    'use strict';

    const TAU = Math.PI * 2;
    const MAX_LEVEL = 5;
    const BOSS_LEVEL = 5;

    // ── Ship skins — you're not just flying a ship, you ARE a detection
    // rule sweeping the graph. Named after the rule formats Rulezet actually
    // supports; palettes only, same silhouette, zero asset cost.
    const SHIP_SKINS = [
        { id: 'yara',     name: 'YARA',     hull: '#dce6ff', glow: '#6ea8ff', flame: '#ffb35c' },
        { id: 'suricata', name: 'Suricata', hull: '#ffe3d8', glow: '#ff7a5c', flame: '#ffe16a' },
        { id: 'sigma',    name: 'Sigma',    hull: '#dcffe6', glow: '#4be08a', flame: '#6af0ff' },
        { id: 'zeek',     name: 'Zeek',     hull: '#e8dcff', glow: '#a06bff', flame: '#ff6bd8' },
    ];

    // ── FontAwesome glyphs drawn straight on canvas (fillText), no DOM
    // nodes needed. Codepoints pulled from the Free 6.3.0 set actually
    // shipped in this project (app/static/fontawesome-6.3.0).
    const FA_FONT = "'Font Awesome 6 Free'";
    const FA_GLYPH = {
        malware: '\uf188', // fa-bug              — asteroids
        threat:  '\uf544', // fa-robot            — chasing aliens
        boss:    '\uf714', // fa-skull-crossbones — the level-5 boss
        rapid:   '\uf0e7', // fa-bolt             — rapid-fire powerup
        shield:  '\uf3ed', // fa-shield-halved    — shield powerup
        heart:   '\uf004', // fa-heart           — extra-life powerup
        lock:    '\uf023', // fa-lock             — locked level chip (menu)
    };
    let faReady = false;
    if (window.document && document.fonts && document.fonts.load) {
        document.fonts.load('900 32px ' + FA_FONT).then(() => { faReady = true; }).catch(() => {});
    }

    // ── Web Audio — tiny procedural sound + music engine ───────────────────
    const Sound = (function () {
        let ctx = null;
        let muted = false;

        function ensure() {
            if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
            if (ctx.state === 'suspended') ctx.resume();
            return ctx;
        }

        function envGain(t0, peak, dur) {
            const g = ensure().createGain();
            g.gain.setValueAtTime(0.0001, t0);
            g.gain.exponentialRampToValueAtTime(peak, t0 + 0.015);
            g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
            return g;
        }

        function laser() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(1100, t0);
            osc.frequency.exponentialRampToValueAtTime(220, t0 + 0.12);
            const g = envGain(t0, 0.06, 0.14);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + 0.15);
        }

        function enemyLaser() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'square';
            osc.frequency.setValueAtTime(500, t0);
            osc.frequency.exponentialRampToValueAtTime(140, t0 + 0.18);
            const g = envGain(t0, 0.045, 0.2);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + 0.2);
        }

        function thrustTick() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'triangle';
            osc.frequency.setValueAtTime(80, t0);
            const g = envGain(t0, 0.025, 0.09);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + 0.09);
        }

        function noiseBurst(dur, filterFreq, peak) {
            const c = ensure();
            const t0 = c.currentTime;
            const bufferSize = Math.floor(c.sampleRate * dur);
            const buffer = c.createBuffer(1, bufferSize, c.sampleRate);
            const data = buffer.getChannelData(0);
            for (let i = 0; i < bufferSize; i++) data[i] = (Math.random() * 2 - 1) * (1 - i / bufferSize);
            const src = c.createBufferSource();
            src.buffer = buffer;
            const filt = c.createBiquadFilter();
            filt.type = 'lowpass';
            filt.frequency.setValueAtTime(filterFreq, t0);
            filt.frequency.exponentialRampToValueAtTime(Math.max(200, filterFreq * 0.2), t0 + dur);
            const g = c.createGain();
            g.gain.setValueAtTime(peak, t0);
            g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
            src.connect(filt).connect(g).connect(c.destination);
            src.start(t0);
        }

        function explode(big) {
            if (muted) return;
            noiseBurst(big ? 0.5 : 0.28, big ? 1400 : 2200, big ? 0.35 : 0.22);
        }

        function hit() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'square';
            osc.frequency.setValueAtTime(180, t0);
            osc.frequency.exponentialRampToValueAtTime(40, t0 + 0.35);
            const g = envGain(t0, 0.18, 0.4);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + 0.4);
        }

        function gameOver() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            // A little descending arcade "game over" jingle, not just a beep.
            [440, 392, 349, 293, 220].forEach((f, i) => {
                const delay = i * 0.16;
                const osc = c.createOscillator();
                osc.type = i < 3 ? 'triangle' : 'sawtooth';
                osc.frequency.setValueAtTime(f, t0 + delay);
                const g = envGain(t0 + delay, i < 3 ? 0.1 : 0.14, i === 4 ? 0.7 : 0.32);
                osc.connect(g).connect(c.destination);
                osc.start(t0 + delay); osc.stop(t0 + delay + (i === 4 ? 0.7 : 0.32));
            });
        }

        function powerup() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            [660, 880, 1100].forEach((f, i) => {
                const osc = c.createOscillator();
                osc.type = 'square';
                osc.frequency.setValueAtTime(f, t0 + i * 0.06);
                const g = envGain(t0 + i * 0.06, 0.08, 0.14);
                osc.connect(g).connect(c.destination);
                osc.start(t0 + i * 0.06); osc.stop(t0 + i * 0.06 + 0.14);
            });
        }

        function extraLife() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            [523, 659, 784, 1046, 1318].forEach((f, i) => {
                const osc = c.createOscillator();
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(f, t0 + i * 0.07);
                const g = envGain(t0 + i * 0.07, 0.11, 0.22);
                osc.connect(g).connect(c.destination);
                osc.start(t0 + i * 0.07); osc.stop(t0 + i * 0.07 + 0.22);
            });
        }

        function countdownBeep(isGo) {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'square';
            osc.frequency.setValueAtTime(isGo ? 880 : 523, t0);
            const g = envGain(t0, isGo ? 0.14 : 0.09, isGo ? 0.3 : 0.15);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + (isGo ? 0.3 : 0.15));
        }

        function victory() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            [523, 659, 784, 1046].forEach((f, i) => {
                const osc = c.createOscillator();
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(f, t0 + i * 0.12);
                const g = envGain(t0 + i * 0.12, 0.14, 0.3);
                osc.connect(g).connect(c.destination);
                osc.start(t0 + i * 0.12); osc.stop(t0 + i * 0.12 + 0.3);
            });
        }

        function levelUp() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            [523, 659, 784].forEach((f, i) => {
                const osc = c.createOscillator();
                osc.type = 'triangle';
                osc.frequency.setValueAtTime(f, t0 + i * 0.09);
                const g = envGain(t0 + i * 0.09, 0.1, 0.2);
                osc.connect(g).connect(c.destination);
                osc.start(t0 + i * 0.09); osc.stop(t0 + i * 0.09 + 0.2);
            });
        }

        function bossHit() {
            if (muted) return;
            const c = ensure();
            const t0 = c.currentTime;
            const osc = c.createOscillator();
            osc.type = 'sawtooth';
            osc.frequency.setValueAtTime(300, t0);
            osc.frequency.exponentialRampToValueAtTime(90, t0 + 0.2);
            const g = envGain(t0, 0.09, 0.22);
            osc.connect(g).connect(c.destination);
            osc.start(t0); osc.stop(t0 + 0.22);
        }

        // ── Background music — small look-ahead scheduler playing a short
        // chiptune-style riff (soft square-wave lead + a light kick pulse).
        // Kept deliberately quiet and short-looping with an occasional
        // transposition so it stays "arcade" without turning grating.
        const Music = (function () {
            let masterGain = null;
            let timer = null;
            let nextNoteTime = 0;
            let step = 0;
            let loops = 0;
            const SCHEDULE_AHEAD = 0.2;
            const TICK_MS = 50;
            const STEP_DUR = 0.19;
            // A minor pentatonic — safe, spacey, never sounds "wrong"
            const SCALE = [220.00, 261.63, 293.66, 329.63, 392.00, 440.00, 523.25];
            // Short 8-step riff (scale degree indices) — simple and catchy
            // rather than a slow ambient drift, but short enough to not wear thin.
            const RIFF = [0, 2, 4, 2, 5, 4, 2, 0];
            const TRANSPOSE_CYCLE = [0, 0, 2, 0]; // shifts up a little every few loops for variety
            let intensity = 0; // 0 = calm menu riff, 1..5 ramps with level
            let paused = false;

            function playLead(t0, freq, dur, vol) {
                const c = ensure();
                const osc = c.createOscillator();
                osc.type = 'square';
                osc.frequency.setValueAtTime(freq, t0);
                const filt = c.createBiquadFilter();
                filt.type = 'lowpass';
                filt.frequency.setValueAtTime(2200, t0); // takes the harsh edge off the square wave
                const g = c.createGain();
                g.gain.setValueAtTime(0.0001, t0);
                g.gain.exponentialRampToValueAtTime(vol, t0 + 0.02);
                g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
                osc.connect(filt).connect(g).connect(masterGain);
                osc.start(t0); osc.stop(t0 + dur);
            }

            function playKick(t0, vol) {
                const c = ensure();
                const osc = c.createOscillator();
                osc.type = 'sine';
                osc.frequency.setValueAtTime(120, t0);
                osc.frequency.exponentialRampToValueAtTime(45, t0 + 0.09);
                const g = c.createGain();
                g.gain.setValueAtTime(vol, t0);
                g.gain.exponentialRampToValueAtTime(0.0001, t0 + 0.11);
                osc.connect(g).connect(masterGain);
                osc.start(t0); osc.stop(t0 + 0.12);
            }

            function scheduleStep() {
                const c = ensure();
                while (nextNoteTime < c.currentTime + SCHEDULE_AHEAD) {
                    if (!muted) {
                        const transpose = TRANSPOSE_CYCLE[loops % TRANSPOSE_CYCLE.length];
                        const degree = RIFF[step % RIFF.length] + transpose;
                        const octave = degree >= SCALE.length ? 1.5 : 1;
                        const freq = SCALE[degree % SCALE.length] * octave;
                        playLead(nextNoteTime, freq, STEP_DUR * 0.85, 0.035 + intensity * 0.008);
                        if (step % 4 === 0) playKick(nextNoteTime, 0.05 + intensity * 0.01);
                    }
                    nextNoteTime += STEP_DUR - intensity * 0.008; // subtly speeds up with intensity
                    step++;
                    if (step % RIFF.length === 0) loops++;
                }
            }

            function start() {
                if (timer) return;
                const c = ensure();
                masterGain = c.createGain();
                masterGain.gain.value = 0.5;
                masterGain.connect(c.destination);
                nextNoteTime = c.currentTime + 0.1;
                step = 0; loops = 0; paused = false;
                timer = setInterval(scheduleStep, TICK_MS);
            }

            function stop() {
                paused = false;
                if (timer) { clearInterval(timer); timer = null; }
                if (masterGain) {
                    try { masterGain.disconnect(); } catch (e) { /* noop */ }
                    masterGain = null;
                }
            }

            // Pause/resume keep the same masterGain alive (no audible glitch)
            // but stop scheduling new notes — used when the game itself pauses.
            function pause() {
                if (!timer) return;
                paused = true;
                clearInterval(timer);
                timer = null;
            }

            function resumeMusic() {
                if (timer || !masterGain) return;
                paused = false;
                nextNoteTime = ensure().currentTime + 0.1;
                timer = setInterval(scheduleStep, TICK_MS);
            }

            function setIntensity(lvl) { intensity = lvl; }

            return { start, stop, pause, resumeMusic, setIntensity };
        })();

        function setMuted(v) { muted = v; }
        function isMuted() { return muted; }

        return {
            laser, enemyLaser, thrustTick, explode, hit, gameOver, victory, levelUp, bossHit,
            powerup, extraLife, countdownBeep,
            setMuted, isMuted, ensure, Music,
        };
    })();

    // ── Helpers ─────────────────────────────────────────────────────────
    function wrap(v, max) {
        if (v < 0) return v + max;
        if (v > max) return v - max;
        return v;
    }
    function clampSpeed(obj, max) {
        const speed = Math.hypot(obj.vx, obj.vy);
        if (speed > max) { obj.vx = obj.vx / speed * max; obj.vy = obj.vy / speed * max; }
    }

    // ── Entity factories ────────────────────────────────────────────────
    function makeShip(w, h, skin) {
        return {
            x: w / 2, y: h / 2, vx: 0, vy: 0, angle: -Math.PI / 2,
            radius: 13, thrusting: false, alive: true, invuln: 0,
            rapid: 0, shield: 0, // frame-counted power-up timers
            skin: skin || SHIP_SKINS[0],
        };
    }

    // ── Power-ups — drop periodically, drift, expire if not collected ────
    const POWERUP_TYPES = {
        rapid:  { glyph: 'rapid',  color: '#ffd447', label: 'RAPID FIRE' },
        shield: { glyph: 'shield', color: '#6ea8ff', label: 'SHIELD' },
        heart:  { glyph: 'heart',  color: '#ff6b8f', label: 'EXTRA LIFE' },
    };
    const RAPID_DURATION  = 480; // ~8s at 60fps
    const SHIELD_DURATION = 420; // ~7s at 60fps

    function makePowerup(x, y, type) {
        const angle = Math.random() * TAU;
        return {
            kind: 'powerup', type, x, y,
            vx: Math.cos(angle) * 0.5, vy: Math.sin(angle) * 0.5,
            radius: 13, life: 600, pulse: Math.random() * TAU,
        };
    }

    function makeAsteroid(x, y, size) {
        // size: 3 = large, 2 = medium, 1 = small
        const speed = 0.4 + (3 - size) * 0.35 + Math.random() * 0.4;
        const dir = Math.random() * TAU;
        const radius = size * 16 + 8;
        const points = [];
        const vertCount = 9 + Math.floor(Math.random() * 4);
        for (let i = 0; i < vertCount; i++) {
            const a = (i / vertCount) * TAU;
            const r = radius * (0.75 + Math.random() * 0.45);
            points.push({ a, r });
        }
        return {
            kind: 'asteroid',
            x, y, vx: Math.cos(dir) * speed, vy: Math.sin(dir) * speed,
            radius, size, points, rot: 0,
            rotSpeed: (Math.random() - 0.5) * 0.02,
        };
    }

    function makeAlien(x, y, canShoot) {
        return {
            kind: 'alien',
            x, y, vx: 0, vy: 0, radius: 14,
            wobble: Math.random() * TAU,
            accel: 0.05 + Math.random() * 0.02,
            maxSpeed: 2.1 + Math.random() * 0.6,
            canShoot, fireTimer: 60 + Math.random() * 60,
            hp: 1,
        };
    }

    function makeBoss(w, h) {
        return {
            kind: 'boss',
            x: w / 2, y: -80, vx: 1.4, vy: 0,
            radius: 46, hp: 46, maxHp: 46,
            fireTimer: 90, moveTimer: 0, entering: true,
        };
    }

    function randomEdgePosition(w, h) {
        const side = Math.floor(Math.random() * 4);
        if (side === 0) return { x: Math.random() * w, y: -30 };
        if (side === 1) return { x: w + 30, y: Math.random() * h };
        if (side === 2) return { x: Math.random() * w, y: h + 30 };
        return { x: -30, y: Math.random() * h };
    }

    // Level design: how many asteroids/aliens per wave, and whether aliens
    // shoot back. Level 5 replaces the wave with a boss fight.
    const LEVEL_CONFIG = {
        1: { asteroids: 3, aliens: 0, alienShoots: false },
        2: { asteroids: 4, aliens: 1, alienShoots: false },
        3: { asteroids: 5, aliens: 2, alienShoots: true },
        4: { asteroids: 6, aliens: 3, alienShoots: true },
    };

    // Shown on the big level-intro card before each sector — keeps tying
    // the game back to what Rulezet actually does.
    const LEVEL_STORY = {
        1: 'First contact. A handful of malware samples drift through the graph — nothing your signatures haven’t already seen.',
        2: 'Escalation. More samples, and the first threat-actor beacon activates. Something out there knows it’s being hunted.',
        3: 'Active pursuit. Beacons are shooting back now. Detection just became a two-way fight.',
        4: 'Saturation. The graph is thick with samples and beacons converging on your position. Hold the line.',
        5: 'No known signature. No CVE. No prior art. Just you, your rule, and whatever this zero-day turns out to be.',
    };

    // ── Main game class ───────────────────────────────────────────────
    function StarfieldGame(canvas, opts) {
        const ctx2d = canvas.getContext('2d');
        let w = 0, h = 0, dpr = Math.min(window.devicePixelRatio || 1, 2);

        const keys = {};
        let ship, bullets, enemyBullets, asteroids, aliens, particles, stars, shootingStars, powerups, boss;
        let score = 0, lives = 3, level = 1;
        let state = 'menu'; // menu | levelintro | countdown | playing | paused | gameover | victory
        let lastShot = 0;
        let animId = null;
        let thrustSoundTimer = 0;
        let shootingStarTimer = 0;
        let powerupTimer = 0;
        let skin = SHIP_SKINS[0];
        let introTimer = null;
        let countdownTimer = null;

        function resize() {
            const rect = canvas.parentElement.getBoundingClientRect();
            w = rect.width; h = rect.height;
            canvas.width = w * dpr; canvas.height = h * dpr;
            canvas.style.width = w + 'px'; canvas.style.height = h + 'px';
            ctx2d.setTransform(dpr, 0, 0, dpr, 0, 0);
        }

        function makeStars() {
            stars = [];
            const count = 90;
            for (let i = 0; i < count; i++) {
                stars.push({
                    x: Math.random() * w, y: Math.random() * h,
                    r: Math.random() * 1.6 + 0.3,
                    tw: Math.random() * TAU,
                    speed: 0.15 + Math.random() * 0.35,
                });
            }
            shootingStars = [];
            shootingStarTimer = 60 + Math.random() * 120;
        }

        function spawnShootingStar() {
            const fromLeft = Math.random() < 0.5;
            const dir = fromLeft ? 1 : -1;
            const y = Math.random() * h * 0.5;
            const speed = 14 + Math.random() * 8; // fast — unlike the slow ambient twinkle stars
            const angle = 0.3 + Math.random() * 0.25; // shallow downward streak
            shootingStars.push({
                x: fromLeft ? -20 : w + 20, y,
                vx: Math.cos(angle) * speed * dir,
                vy: Math.sin(angle) * speed,
                life: 1,
            });
        }

        function resetGame(startLevel) {
            ship = makeShip(w, h, skin);
            bullets = [];
            enemyBullets = [];
            particles = [];
            asteroids = [];
            aliens = [];
            powerups = [];
            powerupTimer = 300 + Math.random() * 300;
            boss = null;
            score = 0; lives = 3;
            level = Math.min(Math.max(startLevel || 1, 1), MAX_LEVEL);
            Sound.Music.setIntensity(level);
            // spawnWave() no longer happens here — it fires after the
            // level-intro card + 3-2-1-GO countdown, see beginLevelSequence().
        }

        // Big "SECTOR N" card + story blurb, then a 3-2-1-GO countdown, THEN
        // the wave actually spawns. Used both for the very first level and
        // for every subsequent level-up.
        function beginLevelSequence(lvl) {
            clearTimeout(introTimer);
            clearInterval(countdownTimer);
            state = 'levelintro';
            opts.onLevelIntro(lvl, LEVEL_STORY[lvl] || '', lvl === BOSS_LEVEL);
            introTimer = setTimeout(() => {
                if (state === 'levelintro') startCountdown();
            }, 3200);
        }

        function startCountdown() {
            state = 'countdown';
            let n = 3;
            opts.onCountdown(n);
            Sound.countdownBeep(false);
            countdownTimer = setInterval(() => {
                n--;
                if (n > 0) {
                    opts.onCountdown(n);
                    Sound.countdownBeep(false);
                } else if (n === 0) {
                    opts.onCountdown('GO!');
                    Sound.countdownBeep(true);
                } else {
                    clearInterval(countdownTimer);
                    opts.onCountdown(null);
                    spawnWave();
                    state = 'playing';
                }
            }, 650);
        }

        function spawnWave() {
            if (level === BOSS_LEVEL) {
                boss = makeBoss(w, h);
                opts.onBoss(boss.hp, boss.maxHp);
                Sound.Music.setIntensity(5);
                return;
            }
            const cfg = LEVEL_CONFIG[level] || LEVEL_CONFIG[4];
            for (let i = 0; i < cfg.asteroids; i++) {
                const pos = randomEdgePosition(w, h);
                asteroids.push(makeAsteroid(pos.x, pos.y, 3));
            }
            for (let i = 0; i < cfg.aliens; i++) {
                const pos = randomEdgePosition(w, h);
                aliens.push(makeAlien(pos.x, pos.y, cfg.alienShoots));
            }
            Sound.Music.setIntensity(level);
        }

        function spawnExplosion(x, y, n, color) {
            for (let i = 0; i < n; i++) {
                const a = Math.random() * TAU;
                const speed = Math.random() * 2.2 + 0.4;
                particles.push({
                    x, y, vx: Math.cos(a) * speed, vy: Math.sin(a) * speed,
                    life: 1, decay: 0.02 + Math.random() * 0.03,
                    color: color || '#ffd27f',
                });
            }
        }

        function shoot() {
            const now = performance.now();
            const rapidOn = ship.rapid > 0;
            if (now - lastShot < (rapidOn ? 90 : 220)) return;
            lastShot = now;
            const speed = 6.2;
            const spread = rapidOn ? [-0.18, 0, 0.18] : [0]; // rapid-fire = 3-way burst
            for (const da of spread) {
                const ang = ship.angle + da;
                bullets.push({
                    x: ship.x + Math.cos(ang) * ship.radius,
                    y: ship.y + Math.sin(ang) * ship.radius,
                    vx: ship.vx + Math.cos(ang) * speed,
                    vy: ship.vy + Math.sin(ang) * speed,
                    life: 60,
                });
            }
            Sound.laser();
        }

        function alienShoot(a) {
            const dx = ship.x - a.x, dy = ship.y - a.y;
            const dist = Math.hypot(dx, dy) || 1;
            const speed = 3.4;
            enemyBullets.push({
                x: a.x, y: a.y,
                vx: (dx / dist) * speed, vy: (dy / dist) * speed,
                life: 90,
            });
            Sound.enemyLaser();
        }

        function bossShoot() {
            const shots = 5;
            const baseAngle = Math.atan2(ship.y - boss.y, ship.x - boss.x);
            for (let i = 0; i < shots; i++) {
                const a = baseAngle + (i - (shots - 1) / 2) * 0.22;
                enemyBullets.push({
                    x: boss.x, y: boss.y,
                    vx: Math.cos(a) * 3.2, vy: Math.sin(a) * 3.2,
                    life: 110,
                });
            }
            Sound.enemyLaser();
        }

        function hitShip() {
            if (ship.invuln > 0 || ship.shield > 0) return;
            lives--;
            Sound.hit();
            spawnExplosion(ship.x, ship.y, 22, ship.skin.glow);
            opts.onScoreChange(score, lives, level);
            if (lives <= 0) {
                endGame();
            } else {
                ship.x = w / 2; ship.y = h / 2; ship.vx = 0; ship.vy = 0;
                ship.invuln = 150;
            }
        }

        function breakAsteroid(ast, index) {
            Sound.explode(ast.size >= 2);
            spawnExplosion(ast.x, ast.y, ast.size * 6 + 6, '#ff5a6b');
            score += (4 - ast.size) * 25;
            opts.onScoreChange(score, lives, level);
            asteroids.splice(index, 1);
            if (ast.size > 1) {
                for (let i = 0; i < 2; i++) asteroids.push(makeAsteroid(ast.x, ast.y, ast.size - 1));
            }
            checkWaveClear();
        }

        function killAlien(a, index) {
            Sound.explode(false);
            spawnExplosion(a.x, a.y, 16, '#ffb020');
            score += 75;
            opts.onScoreChange(score, lives, level);
            aliens.splice(index, 1);
            checkWaveClear();
        }

        function reportBuffs() {
            if (opts.onBuffs) opts.onBuffs({ rapid: ship.rapid, shield: ship.shield });
        }

        function spawnPowerup() {
            const pos = randomEdgePosition(w, h);
            const canHeart = lives < 5;
            const roll = Math.random();
            let type;
            if (canHeart && roll < 0.18) type = 'heart';
            else if (roll < 0.55) type = 'rapid';
            else type = 'shield';
            powerups.push(makePowerup(
                Math.max(30, Math.min(w - 30, pos.x)),
                Math.max(30, Math.min(h - 30, pos.y)),
                type
            ));
        }

        function applyPowerup(type) {
            if (type === 'rapid') {
                ship.rapid = RAPID_DURATION;
                Sound.powerup();
            } else if (type === 'shield') {
                ship.shield = SHIELD_DURATION;
                Sound.powerup();
            } else if (type === 'heart') {
                lives = Math.min(lives + 1, 5);
                Sound.extraLife();
            }
            opts.onScoreChange(score, lives, level);
            reportBuffs();
        }

        function checkWaveClear() {
            if (level === BOSS_LEVEL) return;
            if (asteroids.length === 0 && aliens.length === 0) {
                if (level >= MAX_LEVEL) return;
                level++;
                Sound.levelUp();
                opts.onScoreChange(score, lives, level);
                beginLevelSequence(level);
            }
        }

        function hitBoss(amount) {
            boss.hp -= amount;
            Sound.bossHit();
            spawnExplosion(boss.x + (Math.random() - 0.5) * 40, boss.y + (Math.random() - 0.5) * 40, 6, '#ff8f6b');
            opts.onBoss(Math.max(boss.hp, 0), boss.maxHp);
            if (boss.hp <= 0) {
                spawnExplosion(boss.x, boss.y, 60, '#ffd27f');
                score += 1000;
                opts.onScoreChange(score, lives, level);
                boss = null;
                winGame();
            }
        }

        function endGame() {
            state = 'gameover';
            Sound.Music.stop();
            Sound.gameOver();
            opts.onGameOver(score, level);
        }

        function winGame() {
            state = 'victory';
            Sound.Music.stop();
            Sound.victory();
            opts.onVictory(score);
        }

        function update() {
            if (state !== 'playing') return;

            // Ship controls
            const rotSpeed = 0.055;
            if (keys['ArrowLeft'] || keys['a'] || keys['A']) ship.angle -= rotSpeed;
            if (keys['ArrowRight'] || keys['d'] || keys['D']) ship.angle += rotSpeed;
            ship.thrusting = !!(keys['ArrowUp'] || keys['w'] || keys['W']);
            if (ship.thrusting) {
                ship.vx += Math.cos(ship.angle) * 0.14;
                ship.vy += Math.sin(ship.angle) * 0.14;
                thrustSoundTimer--;
                if (thrustSoundTimer <= 0) { Sound.thrustTick(); thrustSoundTimer = 8; }
            }
            if (keys[' ']) shoot();

            ship.vx *= 0.99; ship.vy *= 0.99;
            clampSpeed(ship, 6.5);
            ship.x = wrap(ship.x + ship.vx, w);
            ship.y = wrap(ship.y + ship.vy, h);
            if (ship.invuln > 0) ship.invuln--;
            const wasRapid = ship.rapid > 0, wasShield = ship.shield > 0;
            if (ship.rapid  > 0) ship.rapid--;
            if (ship.shield > 0) ship.shield--;
            if ((wasRapid && ship.rapid <= 0) || (wasShield && ship.shield <= 0)) reportBuffs();

            // Player bullets
            for (let i = bullets.length - 1; i >= 0; i--) {
                const b = bullets[i];
                b.x = wrap(b.x + b.vx, w);
                b.y = wrap(b.y + b.vy, h);
                b.life--;
                if (b.life <= 0) bullets.splice(i, 1);
            }

            // Enemy bullets
            for (let i = enemyBullets.length - 1; i >= 0; i--) {
                const b = enemyBullets[i];
                b.x += b.vx; b.y += b.vy;
                b.life--;
                if (b.life <= 0 || b.x < -20 || b.x > w + 20 || b.y < -20 || b.y > h + 20) enemyBullets.splice(i, 1);
            }

            // Asteroids drift
            for (const a of asteroids) {
                a.x = wrap(a.x + a.vx, w);
                a.y = wrap(a.y + a.vy, h);
                a.rot += a.rotSpeed;
            }

            // Aliens pursue the ship
            for (const a of aliens) {
                const dx = ship.x - a.x, dy = ship.y - a.y;
                const dist = Math.hypot(dx, dy) || 1;
                a.wobble += 0.06;
                const perpX = -dy / dist, perpY = dx / dist;
                a.vx += (dx / dist) * a.accel + perpX * Math.sin(a.wobble) * 0.03;
                a.vy += (dy / dist) * a.accel + perpY * Math.sin(a.wobble) * 0.03;
                clampSpeed(a, a.maxSpeed);
                a.x = wrap(a.x + a.vx, w);
                a.y = wrap(a.y + a.vy, h);
                if (a.canShoot) {
                    a.fireTimer--;
                    if (a.fireTimer <= 0) { alienShoot(a); a.fireTimer = 100 + Math.random() * 60; }
                }
            }

            // Boss behaviour
            if (boss) {
                if (boss.entering) {
                    boss.y += 1.2;
                    if (boss.y >= 90) boss.entering = false;
                } else {
                    boss.x += boss.vx;
                    if (boss.x < boss.radius || boss.x > w - boss.radius) boss.vx *= -1;
                    boss.moveTimer++;
                    boss.fireTimer--;
                    if (boss.fireTimer <= 0) { bossShoot(); boss.fireTimer = 70; }
                }
            }

            // Player bullets vs asteroids
            outerA:
            for (let ai = asteroids.length - 1; ai >= 0; ai--) {
                const a = asteroids[ai];
                for (let bi = bullets.length - 1; bi >= 0; bi--) {
                    const b = bullets[bi];
                    if (Math.hypot(a.x - b.x, a.y - b.y) < a.radius) {
                        bullets.splice(bi, 1);
                        breakAsteroid(a, ai);
                        continue outerA;
                    }
                }
            }

            // Player bullets vs aliens
            outerB:
            for (let ai = aliens.length - 1; ai >= 0; ai--) {
                const a = aliens[ai];
                for (let bi = bullets.length - 1; bi >= 0; bi--) {
                    const b = bullets[bi];
                    if (Math.hypot(a.x - b.x, a.y - b.y) < a.radius) {
                        bullets.splice(bi, 1);
                        killAlien(a, ai);
                        continue outerB;
                    }
                }
            }

            // Player bullets vs boss
            if (boss) {
                for (let bi = bullets.length - 1; bi >= 0; bi--) {
                    const b = bullets[bi];
                    if (Math.hypot(boss.x - b.x, boss.y - b.y) < boss.radius) {
                        bullets.splice(bi, 1);
                        hitBoss(2);
                        if (!boss) break;
                    }
                }
            }

            // Enemy bullets vs ship — a shield absorbs the hit (with a little
            // spark) instead of just letting it pass through like invuln does.
            if (ship.invuln <= 0) {
                for (let bi = enemyBullets.length - 1; bi >= 0; bi--) {
                    const b = enemyBullets[bi];
                    if (Math.hypot(ship.x - b.x, ship.y - b.y) < ship.radius) {
                        enemyBullets.splice(bi, 1);
                        if (ship.shield > 0) spawnExplosion(b.x, b.y, 6, ship.skin.glow);
                        else hitShip();
                        break;
                    }
                }
            }

            // Ship vs asteroids / aliens / boss (contact damage) — shield blocks it
            if (ship.invuln <= 0 && ship.shield <= 0) {
                let hit = false;
                for (const a of asteroids) {
                    if (Math.hypot(a.x - ship.x, a.y - ship.y) < a.radius + ship.radius * 0.7) { hit = true; break; }
                }
                if (!hit) for (const a of aliens) {
                    if (Math.hypot(a.x - ship.x, a.y - ship.y) < a.radius + ship.radius * 0.7) { hit = true; break; }
                }
                if (!hit && boss && Math.hypot(boss.x - ship.x, boss.y - ship.y) < boss.radius + ship.radius * 0.7) hit = true;
                if (hit) hitShip();
            }

            // Particles
            for (let i = particles.length - 1; i >= 0; i--) {
                const p = particles[i];
                p.x += p.vx; p.y += p.vy;
                p.vx *= 0.97; p.vy *= 0.97;
                p.life -= p.decay;
                if (p.life <= 0) particles.splice(i, 1);
            }

            // Stars drift very slowly for parallax life
            for (const s of stars) {
                s.x -= s.speed * 0.15;
                if (s.x < 0) s.x = w;
                s.tw += 0.05;
            }

            // Fast shooting stars — purely decorative, spawned on a random timer
            shootingStarTimer--;
            if (shootingStarTimer <= 0) {
                spawnShootingStar();
                shootingStarTimer = 90 + Math.random() * 150;
            }
            for (let i = shootingStars.length - 1; i >= 0; i--) {
                const s = shootingStars[i];
                s.x += s.vx; s.y += s.vy;
                s.life -= 0.02;
                if (s.life <= 0 || s.x < -40 || s.x > w + 40 || s.y > h + 40) shootingStars.splice(i, 1);
            }

            // Power-ups — rapid-fire bolt, shield, and the occasional heart
            powerupTimer--;
            if (powerupTimer <= 0) {
                spawnPowerup();
                powerupTimer = 600 + Math.random() * 500; // roughly every 10-18s
            }
            for (let i = powerups.length - 1; i >= 0; i--) {
                const p = powerups[i];
                p.x = wrap(p.x + p.vx, w);
                p.y = wrap(p.y + p.vy, h);
                p.pulse += 0.08;
                p.life--;
                if (p.life <= 0) { powerups.splice(i, 1); continue; }
                if (Math.hypot(p.x - ship.x, p.y - ship.y) < p.radius + ship.radius) {
                    spawnExplosion(p.x, p.y, 14, POWERUP_TYPES[p.type].color);
                    applyPowerup(p.type);
                    powerups.splice(i, 1);
                }
            }
        }

        function drawShip() {
            if (!ship.alive) return;
            if (ship.invuln > 0 && Math.floor(ship.invuln / 6) % 2 === 0) return; // blink

            if (ship.shield > 0) {
                ctx2d.save();
                ctx2d.translate(ship.x, ship.y);
                const pulse = 1 + Math.sin(performance.now() / 120) * 0.08;
                ctx2d.beginPath();
                ctx2d.arc(0, 0, (ship.radius + 8) * pulse, 0, TAU);
                ctx2d.strokeStyle = '#6ea8ff';
                ctx2d.lineWidth = 2;
                ctx2d.shadowColor = '#6ea8ff';
                ctx2d.shadowBlur = 10;
                ctx2d.globalAlpha = 0.75;
                ctx2d.stroke();
                ctx2d.globalAlpha = 1;
                ctx2d.restore();
            }

            ctx2d.save();
            ctx2d.translate(ship.x, ship.y);
            ctx2d.rotate(ship.angle);
            ctx2d.beginPath();
            ctx2d.moveTo(16, 0);
            ctx2d.lineTo(-11, 9);
            ctx2d.lineTo(-6, 0);
            ctx2d.lineTo(-11, -9);
            ctx2d.closePath();
            ctx2d.fillStyle = ship.skin.hull;
            ctx2d.shadowColor = ship.skin.glow;
            ctx2d.shadowBlur = 10;
            ctx2d.fill();
            ctx2d.lineWidth = 1.2;
            ctx2d.strokeStyle = ship.skin.glow;
            ctx2d.stroke();

            if (ship.thrusting) {
                ctx2d.beginPath();
                const flick = 6 + Math.random() * 6;
                ctx2d.moveTo(-6, 3.5);
                ctx2d.lineTo(-6 - flick, 0);
                ctx2d.lineTo(-6, -3.5);
                ctx2d.fillStyle = ship.skin.flame;
                ctx2d.shadowColor = ship.skin.flame;
                ctx2d.shadowBlur = 12;
                ctx2d.fill();
            }
            ctx2d.restore();
        }

        // Draws a FontAwesome glyph centered at the current (already
        // translated) origin. Silently no-ops until the webfont is ready,
        // so callers keep a vector fallback for the first frame or two.
        function drawGlyph(glyph, size, color) {
            if (!faReady || !glyph) return false;
            ctx2d.font = '900 ' + size + 'px ' + FA_FONT;
            ctx2d.textAlign = 'center';
            ctx2d.textBaseline = 'middle';
            ctx2d.fillStyle = color;
            ctx2d.shadowColor = color;
            ctx2d.shadowBlur = 6;
            ctx2d.fillText(glyph, 0, 1);
            return true;
        }

        // Asteroids are drawn as drifting malware samples — jagged,
        // corrupted-looking blobs in a hostile red palette, with a bug
        // icon riding along for the win.
        function drawAsteroid(a) {
            ctx2d.save();
            ctx2d.translate(a.x, a.y);
            ctx2d.rotate(a.rot);
            ctx2d.beginPath();
            a.points.forEach((p, i) => {
                const x = Math.cos(p.a) * p.r, y = Math.sin(p.a) * p.r;
                if (i === 0) ctx2d.moveTo(x, y); else ctx2d.lineTo(x, y);
            });
            ctx2d.closePath();
            ctx2d.fillStyle = 'rgba(255, 90, 90, 0.14)';
            ctx2d.strokeStyle = '#ff5a6b';
            ctx2d.lineWidth = 1.4;
            ctx2d.shadowColor = '#ff5a6b';
            ctx2d.shadowBlur = 6;
            ctx2d.fill();
            ctx2d.stroke();
            ctx2d.shadowBlur = 0;
            if (!drawGlyph(FA_GLYPH.malware, a.radius * 0.85, '#ff9494')) {
                // vector fallback while the webfont is still loading
                ctx2d.beginPath();
                ctx2d.moveTo(-a.radius * 0.18, -a.radius * 0.18);
                ctx2d.lineTo(a.radius * 0.18, a.radius * 0.18);
                ctx2d.moveTo(a.radius * 0.18, -a.radius * 0.18);
                ctx2d.lineTo(-a.radius * 0.18, a.radius * 0.18);
                ctx2d.strokeStyle = 'rgba(255,150,150,.55)';
                ctx2d.lineWidth = 1;
                ctx2d.stroke();
            }
            ctx2d.restore();
        }

        // Aliens are threat-actor beacons actively hunting the ship — a
        // hostile amber glow with a little robot riding shotgun.
        function drawAlien(a) {
            ctx2d.save();
            ctx2d.translate(a.x, a.y);
            ctx2d.beginPath();
            ctx2d.ellipse(0, 0, 14, 7, 0, 0, TAU);
            ctx2d.fillStyle = 'rgba(255, 176, 32, 0.18)';
            ctx2d.strokeStyle = '#ffb020';
            ctx2d.lineWidth = 1.4;
            ctx2d.shadowColor = '#ffb020';
            ctx2d.shadowBlur = 8;
            ctx2d.fill(); ctx2d.stroke();
            ctx2d.shadowBlur = 0;
            if (!drawGlyph(FA_GLYPH.threat, 13, '#ffd27a')) {
                ctx2d.beginPath();
                ctx2d.arc(0, -4, 5, Math.PI, TAU);
                ctx2d.fillStyle = 'rgba(255,176,32,.4)';
                ctx2d.fill();
            }
            ctx2d.restore();
        }

        function drawBoss() {
            ctx2d.save();
            ctx2d.translate(boss.x, boss.y);
            const spikes = 10;
            ctx2d.beginPath();
            for (let i = 0; i < spikes; i++) {
                const a = (i / spikes) * TAU;
                const r = boss.radius * (i % 2 === 0 ? 1 : 0.78);
                const x = Math.cos(a) * r, y = Math.sin(a) * r;
                if (i === 0) ctx2d.moveTo(x, y); else ctx2d.lineTo(x, y);
            }
            ctx2d.closePath();
            ctx2d.fillStyle = 'rgba(255, 100, 80, 0.16)';
            ctx2d.strokeStyle = '#ff6b4f';
            ctx2d.lineWidth = 2;
            ctx2d.shadowColor = '#ff6b4f';
            ctx2d.shadowBlur = 16;
            ctx2d.fill(); ctx2d.stroke();
            ctx2d.shadowBlur = 0;
            if (!drawGlyph(FA_GLYPH.boss, boss.radius * 0.8, '#ffcaa8')) {
                ctx2d.beginPath();
                ctx2d.arc(0, 0, boss.radius * 0.4, 0, TAU);
                ctx2d.fillStyle = 'rgba(255,180,80,.5)';
                ctx2d.fill();
            }
            ctx2d.restore();
        }

        function drawPowerup(p) {
            const info = POWERUP_TYPES[p.type];
            const bob = Math.sin(p.pulse) * 3;
            ctx2d.save();
            ctx2d.translate(p.x, p.y + bob);
            ctx2d.beginPath();
            ctx2d.arc(0, 0, p.radius, 0, TAU);
            ctx2d.fillStyle = info.color + '2e';
            ctx2d.strokeStyle = info.color;
            ctx2d.lineWidth = 1.6;
            ctx2d.shadowColor = info.color;
            ctx2d.shadowBlur = 10;
            ctx2d.fill(); ctx2d.stroke();
            ctx2d.shadowBlur = 0;
            if (!drawGlyph(FA_GLYPH[info.glyph], p.radius * 1.05, info.color)) {
                ctx2d.beginPath();
                ctx2d.arc(0, 0, p.radius * 0.4, 0, TAU);
                ctx2d.fillStyle = info.color;
                ctx2d.fill();
            }
            ctx2d.restore();
        }

        function draw() {
            ctx2d.clearRect(0, 0, w, h);

            for (const s of stars) {
                const alpha = 0.35 + Math.sin(s.tw) * 0.35;
                ctx2d.beginPath();
                ctx2d.arc(s.x, s.y, s.r, 0, TAU);
                ctx2d.fillStyle = `rgba(255,255,255,${Math.max(0, alpha)})`;
                ctx2d.fill();
            }

            for (const s of shootingStars) {
                const tailX = s.x - s.vx * 2.2, tailY = s.y - s.vy * 2.2;
                const grad = ctx2d.createLinearGradient(s.x, s.y, tailX, tailY);
                grad.addColorStop(0, `rgba(255,255,255,${s.life})`);
                grad.addColorStop(1, 'rgba(255,255,255,0)');
                ctx2d.strokeStyle = grad;
                ctx2d.lineWidth = 2;
                ctx2d.beginPath();
                ctx2d.moveTo(s.x, s.y);
                ctx2d.lineTo(tailX, tailY);
                ctx2d.stroke();
            }

            for (const a of asteroids) drawAsteroid(a);
            for (const a of aliens) drawAlien(a);
            for (const p of powerups) drawPowerup(p);
            if (boss) drawBoss();

            ctx2d.fillStyle = '#bfe0ff';
            for (const b of bullets) {
                ctx2d.beginPath();
                ctx2d.arc(b.x, b.y, 2.2, 0, TAU);
                ctx2d.shadowColor = '#bfe0ff';
                ctx2d.shadowBlur = 8;
                ctx2d.fill();
            }
            ctx2d.fillStyle = '#ff8f6b';
            for (const b of enemyBullets) {
                ctx2d.beginPath();
                ctx2d.arc(b.x, b.y, 2.6, 0, TAU);
                ctx2d.shadowColor = '#ff8f6b';
                ctx2d.shadowBlur = 8;
                ctx2d.fill();
            }
            ctx2d.shadowBlur = 0;

            for (const p of particles) {
                ctx2d.globalAlpha = Math.max(p.life, 0);
                ctx2d.fillStyle = p.color;
                ctx2d.beginPath();
                ctx2d.arc(p.x, p.y, 2, 0, TAU);
                ctx2d.fill();
            }
            ctx2d.globalAlpha = 1;

            drawShip();
        }

        function loop() {
            update();
            draw();
            animId = requestAnimationFrame(loop);
        }

        function start(chosenSkin, startLevel) {
            if (chosenSkin) skin = chosenSkin;
            resize();
            makeStars();
            resetGame(startLevel);
            opts.onScoreChange(score, lives, level);
            Sound.Music.start();
            if (!animId) loop();
            beginLevelSequence(level);
        }

        function togglePause() {
            if (state === 'playing') { state = 'paused'; Sound.Music.pause(); opts.onPause(); }
            else if (state === 'paused') { state = 'playing'; Sound.Music.resumeMusic(); opts.onResume(); }
        }

        window.addEventListener('keydown', (e) => {
            keys[e.key] = true;
            if (e.key === ' ') e.preventDefault();
            if ((e.key === 'p' || e.key === 'P' || e.key === 'Escape') && (state === 'playing' || state === 'paused')) {
                togglePause();
            }
        });
        window.addEventListener('keyup', (e) => { keys[e.key] = false; });
        window.addEventListener('resize', () => { resize(); if (stars) makeStars(); });

        return {
            start,
            resume: () => { state = 'playing'; Sound.Music.resumeMusic(); },
            stop: () => {
                state = 'menu';
                clearTimeout(introTimer);
                clearInterval(countdownTimer);
                Sound.Music.stop();
            },
            isPaused: () => state === 'paused',
        };
    }

    window.StarfieldGame = StarfieldGame;
    window.StarfieldSound = Sound;
    window.STARFIELD_SKINS = SHIP_SKINS;
})();
