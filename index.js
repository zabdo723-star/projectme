
const express = require('express');
const admin = require('firebase-admin');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
let serviceAccount;
try {
    if (process.env.FIREBASE_SERVICE_ACCOUNT) {
        serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
    } else {
        serviceAccount = require('./serviceAccountKey.json');
    }
} catch (error) {
    console.error("❌ Service Account Error - Check Env Vars", error);
}

if (!admin.apps.length) {
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount)
    });
}

const db = admin.firestore();

const { createClient } = require('@supabase/supabase-js');
const supabase = createClient(
    process.env.SUPABASE_URL || "",
    process.env.SUPABASE_SERVICE_ROLE_KEY || ""
);

const app = express();
app.use(helmet());
app.use(bodyParser.json({ limit: '90kb' }));
app.use(cors({
    origin: function (origin, callback) {
        const isLocal = !origin || /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
        const isProd = origin === 'https://smartattendancepro-code.github.io'
            || origin === 'https://smart-attendance-pro-sap.web.app'
            || origin === 'https://smart-attendance-pro-sap.firebaseapp.com';

        if (isLocal || isProd) {
            callback(null, true);
        } else {
            console.warn('🚫 CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));
const globalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "⛔ طلبات كتير أوي، حاول تاني بعد شوية" }
});
app.use('/api/', globalLimiter);

const COLLEGE_COORDS = {
    lat: 30.385873919506743,
    lng: 30.488794680472196
};
const MAX_DISTANCE_KM = 2.5;

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: "Missing Token" });
    }
    try {
        const idToken = authHeader.split('Bearer ')[1];
        req.user = await admin.auth().verifyIdToken(idToken);
        next();
    } catch (error) {
        return res.status(403).json({ error: "Invalid Token" });
    }
};


const verifyStaffRole = async (req, res, next) => {
    try {
        const uid = req.user.uid;
        const docSnap = await db.collection("faculty_members").doc(uid).get();

        if (docSnap.exists) {
            const userData = docSnap.data();
            if (userData.role === 'dean' || userData.role === 'doctor') {
                return next();
            }
        }

        return res.status(403).json({ error: "Access Denied: Staff Only" });
    } catch (e) {
        res.status(500).json({ error: "Security Check Failed" });
    }
};

function getEgyptTimeInfo(msOrDate = new Date()) {
    const dateObj = typeof msOrDate === 'number' ? new Date(msOrDate) : msOrDate;

    const dateStr = new Intl.DateTimeFormat('en-GB', {
        timeZone: 'Africa/Cairo',
        day: '2-digit', month: '2-digit', year: 'numeric'
    }).format(dateObj);

    const timeStr = new Intl.DateTimeFormat('en-US', {
        timeZone: 'Africa/Cairo',
        hour: '2-digit', minute: '2-digit', hour12: true
    }).format(dateObj);

    return { dateStr, timeStr };
}

function calculateDistance(lat1, lon1, lat2, lon2) {
    if (!lat1 || !lon1 || !lat2 || !lon2) return 9999;
    const R = 6371;
    const dLat = (lat2 - lat1) * Math.PI / 180;
    const dLon = (lon2 - lon1) * Math.PI / 180;
    const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
        Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
        Math.sin(dLon / 2) * Math.sin(dLon / 2);
    const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
    return R * c;
}

app.get('/', (req, res) => {
    res.status(200).send("🦅 Nursing System Backend is Running (Bulletproof V6)");
});


app.get('/api/config', (req, res) => {
    res.json({
        authDomain: "attendance-system-pro-dbdf1.firebaseapp.com",
        projectId: "attendance-system-pro-dbdf1",
        messagingSenderId: "1094544109334",
        appId: "1:1094544109334:web:a7395159d617b3e6e82a37"
    });
});

app.post('/api/verifyOfflinePattern', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, patternPath } = req.body;

        if (!sessionPin || !patternPath) {
            return res.status(400).json({ error: "بيانات ناقصة" });
        }

        const attemptRef = db.collection('rate_limits').doc(`pattern_${studentUID}`);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;

        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - data.updatedAt?.toMillis()) > 60_000;
            if (expired) {
                await attemptRef.delete();
            } else {
                attempts = data.attempts || 0;
            }
        }

        if (attempts >= 2) {
            return res.status(429).json({
                error: "⛔ تجاوزت عدد المحاولات",
                attemptsLeft: 0
            });
        }

        const codeSnap = await db
            .collection('issued_codes_logs')
            .doc(sessionPin)
            .get();

        if (!codeSnap.exists) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }

        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;

        if (codeData.allowOffline === false) {
            return res.status(403).json({ error: "❌ عذراً، قام محاضر المادة بإيقاف ميزة التسجيل الأوفلاين لهذه الجلسة." });
        }

        const sessionPassword = codeData.offlinePattern || null;

        if (!sessionPassword) {
            return res.status(200).json({
                success: true,
                verifyToken: 'NO_PATTERN'
            });
        }
        const serverPass = JSON.parse(sessionPassword);

        if (serverPass?.type === 'pattern') {
            if (!Array.isArray(patternPath) || patternPath.length < 3) {
                return res.status(403).json({ error: "❌ النمط مطلوب" });
            }

            let isMatch = false;
            if (serverPass.mapping) {
                const mappedStudentPath = patternPath.map(
                    idx => serverPass.mapping[idx]
                );
                isMatch = JSON.stringify(mappedStudentPath) ===
                    JSON.stringify(serverPass.path);
            } else {
                isMatch = JSON.stringify(patternPath) ===
                    JSON.stringify(serverPass.path);
            }

            if (!isMatch) {
                await attemptRef.set({
                    attempts: admin.firestore.FieldValue.increment(1),
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                }, { merge: true });

                return res.status(403).json({
                    error: "❌ النمط غير صحيح",
                    attemptsLeft: 2 - (attempts + 1)
                });
            }
        }

        const crypto = require('crypto');
        const verifyToken = crypto.randomBytes(32).toString('hex');
        await db.collection('pattern_tokens')
            .doc(`${studentUID}_${sessionPin}`)
            .set({
                token: verifyToken,
                sessionPin: sessionPin,
                expiresAt: admin.firestore.Timestamp.fromMillis(Date.now() + 30_000)
            });

        await attemptRef.delete();

        res.status(200).json({ success: true, verifyToken });

    } catch (e) {
        console.error('Offline pattern verify error:', e);
        res.status(500).json({ error: "خطأ في السيرفر" });
    }
});

app.post('/api/syncPostSessionAttendance', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, submissionTime, deviceId } = req.body;
        const safeDeviceId = typeof deviceId === 'string' ? deviceId.slice(0, 100) : 'UNKNOWN_DEVICE';

        if (typeof sessionPin !== 'string' || !/^\d{6}$/.test(sessionPin)) {
            return res.status(400).json({ error: "كود الجلسة غير صالح" });
        }
        if (typeof submissionTime !== 'number' || submissionTime <= 0 || submissionTime > Date.now() + 5000) {
            return res.status(400).json({ error: "وقت التسجيل غير صالح" });
        }

        const attemptRef = db.collection('rate_limits').doc(`postsync_${studentUID}`);

        const [attemptSnap, studentSnap, codeSnap] = await Promise.all([
            attemptRef.get(),
            db.collection('user_registrations').doc(studentUID).get(),
            db.collection('issued_codes_logs').doc(sessionPin).get()
        ]);

        let attempts = 0;
        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - (data.updatedAt?.toMillis() || 0)) > 60_000;
            if (expired) {
                await attemptRef.delete();
            } else {
                attempts = data.attempts || 0;
            }
        }
        if (attempts >= 5) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }

        if (!studentSnap.exists) {
            return res.status(404).json({ error: "بيانات الطالب غير موجودة" });
        }
        const sData = studentSnap.data();
        const info = sData.registrationInfo || sData;
        const studentID = String(info.studentID || sData.studentID || '').trim();
        if (!studentID) {
            return res.status(403).json({ error: "رقم جامعي غير موثق" });
        }

        if (!codeSnap.exists) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }
        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;
        if (!doctorUID) {
            return res.status(500).json({ error: "بيانات الجلسة تالفة" });
        }

        if (codeData.allowOffline === false) {
            await attemptRef.delete().catch(() => { });
            return res.status(403).json({ error: "❌ عذراً، قام محاضر المادة بإيقاف ميزة التسجيل الأوفلاين لهذه الجلسة." });
        }
        const college = /^[A-Za-z0-9_]+$/.test(codeData.college || '') ? codeData.college : "NURS";
        const rawSubject = (codeData.subject || "General").toString();

        const sessionPassword = codeData.offlinePattern || null;

        const { offlineVerifyToken } = req.body;
        let patternTokenRef = null;

        if (sessionPassword) {
            if (!offlineVerifyToken) {
                return res.status(403).json({ error: "❌ التحقق من النمط مطلوب" });
            }
            patternTokenRef = db.collection('pattern_tokens').doc(`${studentUID}_${sessionPin}`);
            const tokenSnap = await patternTokenRef.get();

            const tokenValid = tokenSnap.exists &&
                tokenSnap.data().token === offlineVerifyToken &&
                tokenSnap.data().expiresAt.toMillis() > submissionTime;

            if (!tokenValid) {
                const dupCheck = await db.collection('offline_attendance_log')
                    .where('studentUID', '==', studentUID)
                    .where('sessionPin', '==', sessionPin)
                    .limit(5)
                    .get();
                const dup = dupCheck.docs.find(d => d.data().submissionTime === submissionTime);
                if (dup) {
                    return res.status(200).json({ success: true, recID: dup.id, alreadySynced: true });
                }
                return res.status(403).json({ error: "❌ التحقق من النمط مطلوب أو انتهت صلاحيته" });
            }
        }
        const sessionSnap = await db.collection('active_sessions').doc(doctorUID).get();
        const sessionData = sessionSnap.exists ? sessionSnap.data() : {};

        if (sessionData.isActive === true && sessionData.sessionCode === sessionPin) {
            return res.status(409).json({ error: "الجلسة لسه مفتوحة، استخدم المسار العادي" });
        }

        const openedAtMs = codeData.openedAt?.toMillis
            ? codeData.openedAt.toMillis()
            : Number(codeData.openedAt) || 0;
        const OFFLINE_WINDOW_MS = 25_000;
        const LOOSE_DRIFT = 4000;

        if (submissionTime < (openedAtMs - LOOSE_DRIFT) || submissionTime > (openedAtMs + OFFLINE_WINDOW_MS + LOOSE_DRIFT)) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(403).json({ error: "❌ خارج نافذة التسجيل المسموحة" });
        }

        const { dateStr: fixedDateStr, timeStr: finalTimeStr } = getEgyptTimeInfo(submissionTime);
        const safeDateID = fixedDateStr.replace(/\//g, '-');
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');
        const recID = `${studentID}_${safeDateID}_${cleanSubKey}`;

        const payload = {
            id: studentID,
            sessionPin,
            name: info.fullName || sData.fullName || "Student",
            subject: rawSubject,
            college,
            hall: codeData.hall || "Hall",
            group: info.group || "GENERAL",
            date: fixedDateStr,
            time_str: finalTimeStr,
            timestamp: admin.firestore.Timestamp.fromMillis(submissionTime),
            status: "ATTENDED",
            doctorUID,
            doctorName: codeData.doctorName || "Doctor",
            notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)",
            isOfflineSync: true,
            isPostSession: true,
            feedback_status: "pending",
            feedback_rating: 0,
        };

        const batch = db.batch();

        batch.set(db.collection(`attendance_${college}`).doc(recID), payload);


        batch.set(db.collection('offline_attendance_log').doc(recID), {
            studentID, sessionPin, submissionTime, studentUID,
            deviceId: safeDeviceId,
            syncTimestamp: admin.firestore.FieldValue.serverTimestamp(),
            syncStatus: "SUCCESS_POST_SESSION_BACKEND_V3"
        });

        batch.set(db.collection('student_stats').doc(studentUID), {
            [`attended.${cleanSubKey}`]: admin.firestore.FieldValue.increment(1),
            last_attendance: admin.firestore.FieldValue.serverTimestamp(),
            fullName: payload.name,
            studentID: studentID,
            group: payload.group,
            college: college
        }, { merge: true });

        batch.set(db.collection('user_registrations').doc(studentUID), {
            pendingFeedback: {
                attendanceDocId: recID,
                subject: rawSubject,
                doctorName: codeData.doctorName || "Doctor",
                createdAt: admin.firestore.FieldValue.serverTimestamp()
            }
        }, { merge: true });

        if (patternTokenRef) {
            batch.delete(patternTokenRef);
        }

        await Promise.all([
            batch.commit(),
            attemptRef.delete().catch(() => { })
        ]);

        console.log(`✅ Post-Session Sync | Student: ${studentID} | Doctor: ${doctorUID} | PIN: ${sessionPin}`);

        try {
            const { error: supErr } = await supabase
                .from('attendance_logs')
                .upsert([{
                    student_id: studentID,
                    student_name: payload.name,
                    subject_name: rawSubject,
                    college: college,
                    hall: codeData.hall || "",
                    target_group: payload.group,
                    sis_code: codeData.sisCode || "",
                    session_date: fixedDateStr,
                    attendance_time: payload.time_str,
                    status: "ATTENDED",
                    is_unruly: false,
                    is_uniform_violation: false,
                    notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)",
                    doctor_uid: doctorUID,
                    doctor_name: codeData.doctorName || "Doctor",
                    is_recovered: false,
                    feedback_status: "pending",
                    feedback_rating: 0,
                    segment_count: 1,
                    is_offline_sync: true,
                    level: info.level || "-",
                    group_name: payload.group,
                    is_suspicious: false,
                    trap_is_in_range: null,
                    trap_is_device_match: null,
                    trap_gps_success: null,
                    trap_distance_km: null,
                }], {
                    onConflict: 'student_id,subject_name,session_date,doctor_uid'

                });

            if (supErr) console.error("❌ Supabase sync error:", supErr);
            else console.log(`✅ Supabase synced | Student: ${studentID} | PIN: ${sessionPin}`);
        } catch (supEx) {
            console.error("❌ Supabase exception:", supEx.message);
        }

        res.status(200).json({ success: true, recID });

    } catch (error) {
        console.error("❌ syncPostSessionAttendance Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر، حاول مجدداً" });
    }
});

app.post('/api/syncFeedback', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { studentId, doctorUID, subject, date, rating } = req.body;

        if (!studentId || !doctorUID || !subject || !date || !rating) {
            return res.status(400).json({ error: "بيانات ناقصة" });
        }

        const { error, data } = await supabase
            .from('attendance_logs')
            .update({
                feedback_status: 'submitted',
                feedback_rating: parseInt(rating)
            })
            .match({
                student_id: studentId,
                doctor_uid: doctorUID,
                subject_name: subject,
                session_date: date
            })
            .select();

        if (error) {
            console.error("❌ Supabase Feedback Sync Error:", error);
            return res.status(500).json({ error: error.message });
        }

        console.log(`✅ Feedback synced | Student: ${studentId} | UID: ${studentUID} | Rating: ${rating} | Rows: ${data?.length || 0}`);
        res.status(200).json({ success: true, updated: data?.length || 0 });

    } catch (e) {
        console.error("❌ syncFeedback Exception:", e);
        res.status(500).json({ error: e.message });
    }
});


app.post('/api/syncLiveOfflineAttendance', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, submissionTime, patternInput, offlineVerifyToken, deviceId } = req.body;
        const safeDeviceId = typeof deviceId === 'string' ? deviceId.slice(0, 100) : 'UNKNOWN_DEVICE';

        if (typeof sessionPin !== 'string' || !/^\d{6}$/.test(sessionPin)) {
            return res.status(400).json({ error: "كود الجلسة غير صالح" });
        }
        if (typeof submissionTime !== 'number' || submissionTime <= 0 || submissionTime > Date.now() + 5000) {
            return res.status(400).json({ error: "وقت التسجيل غير صالح" });
        }

        const attemptRef = db.collection('rate_limits').doc(`livesync_${studentUID}`);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;
        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - (data.updatedAt?.toMillis() || 0)) > 60_000;
            if (expired) await attemptRef.delete();
            else attempts = data.attempts || 0;
        }
        if (attempts >= 5) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }

        const studentSnap = await db.collection('user_registrations').doc(studentUID).get();
        if (!studentSnap.exists) return res.status(404).json({ error: "بيانات الطالب غير موجودة" });
        const sData = studentSnap.data();
        const info = sData.registrationInfo || sData;
        const studentID = String(info.studentID || sData.studentID || '').trim();
        if (!studentID) return res.status(403).json({ error: "رقم جامعي غير موثق" });

        const codeSnap = await db.collection('issued_codes_logs').doc(sessionPin).get();
        if (!codeSnap.exists) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }
        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;
        if (!doctorUID) return res.status(500).json({ error: "بيانات الجلسة تالفة" });



        if (codeData.allowOffline === false) {
            await attemptRef.delete().catch(() => { });
            return res.status(403).json({ error: "❌ عذراً، قام محاضر المادة بإيقاف ميزة التسجيل الأوفلاين لهذه الجلسة." });
        }
        const college = /^[A-Za-z0-9_]+$/.test(codeData.college || '') ? codeData.college : "NURS";
        const rawSubject = (codeData.subject || "General").toString();

        const sessionSnap = await db.collection('active_sessions').doc(doctorUID).get();
        const sessionData = sessionSnap.exists ? sessionSnap.data() : {};
        if (sessionData.isActive === true && sessionData.sessionCode !== sessionPin) {
            return res.status(410).json({ error: "❌ انتهت صلاحية هذا الكود — تم إصدار كود جديد للجلسة" });
        }
        if (!(sessionData.isActive === true && sessionData.sessionCode === sessionPin)) {
            return res.status(409).json({ error: "الجلسة مقفولة، استخدم مسار ما بعد الجلسة" });
        }

        const participantRef = db.collection('active_sessions').doc(doctorUID).collection('participants').doc(studentUID);
        const participantSnap = await participantRef.get();
        const preservedSegmentCount = participantSnap.exists ? (participantSnap.data().segment_count || 1) : 1;

        const sessionPassword = codeData.offlinePattern || null;

        let patternTokenRef = null;
        if (sessionPassword) {
            if (!offlineVerifyToken || !patternInput) {
                return res.status(403).json({ error: "بيانات الباترن ناقصة" });
            }
            patternTokenRef = db.collection('pattern_tokens').doc(`${studentUID}_${sessionPin}`);
            const tokenSnap = await patternTokenRef.get();
            const tokenValid = tokenSnap.exists &&
                tokenSnap.data().token === offlineVerifyToken &&
                tokenSnap.data().expiresAt.toMillis() > submissionTime;
            if (!tokenValid) {
                const dupCheck = await db.collection('offline_attendance_log')
                    .where('studentUID', '==', studentUID)
                    .where('sessionPin', '==', sessionPin)
                    .limit(5)
                    .get();
                const dup = dupCheck.docs.find(d => d.data().submissionTime === submissionTime);
                if (dup) {
                    return res.status(200).json({ success: true, recID: dup.id, alreadySynced: true });
                }
                return res.status(403).json({ error: "❌ التحقق من النمط مطلوب أو انتهت صلاحيته" });
            }
        }

        const openedAtMs = codeData.openedAt?.toMillis
            ? codeData.openedAt.toMillis()
            : Number(codeData.openedAt) || 0;
        const OFFLINE_WINDOW_MS = 25_000;
        const LOOSE_DRIFT = 4000;
        if (submissionTime < (openedAtMs - LOOSE_DRIFT) || submissionTime > (openedAtMs + OFFLINE_WINDOW_MS + LOOSE_DRIFT)) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(403).json({ error: "❌ خارج نافذة التسجيل المسموحة" });
        }

        const { dateStr: fixedDateStr, timeStr: finalTimeStr } = getEgyptTimeInfo(submissionTime);
        const safeDateID = fixedDateStr.replace(/\//g, '-');
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');
        const recID = `${studentID}_${safeDateID}_${cleanSubKey}`;

        const payload = {
            id: studentID,
            sessionPin,
            name: info.fullName || sData.fullName || "Student",
            subject: rawSubject,
            college,
            hall: codeData.hall || "Hall",
            group: info.group || "GENERAL",
            date: fixedDateStr,
            time_str: finalTimeStr,
            timestamp: admin.firestore.Timestamp.fromMillis(submissionTime),
            status: "ATTENDED",
            doctorUID,
            doctorName: codeData.doctorName || "Doctor",
            notes: "منضبط (أوفلاين - أثناء الجلسة)",
            isOfflineSync: true,
            feedback_status: "pending",
            feedback_rating: 0,
        };

        const batch = db.batch();
        batch.set(db.collection(`attendance_${college}`).doc(recID), payload);
        batch.set(participantRef, {
            id: studentID, uid: studentUID, name: payload.name,
            status: "active", timestamp: admin.firestore.FieldValue.serverTimestamp(),
            isOfflineSync: true, submissionTime, segment_count: preservedSegmentCount
        });
        batch.set(db.collection('offline_attendance_log').doc(recID), {
            studentID, sessionPin, submissionTime, studentUID,
            deviceId: safeDeviceId,
            syncTimestamp: admin.firestore.FieldValue.serverTimestamp(),
            syncStatus: "SUCCESS_LIVE_BACKEND_V1"
        });

        if (patternTokenRef) {
            batch.delete(patternTokenRef);
        }

        await Promise.all([batch.commit(), attemptRef.delete().catch(() => { })]);

        res.status(200).json({ success: true, recID });

    } catch (error) {
        console.error("❌ syncLiveOfflineAttendance Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر، حاول مجدداً" });
    }
});

app.post('/api/syncOfflineAttendance', verifyToken, async (req, res) => {
    try {
        const studentUID = req.user.uid;
        const { sessionPin, submissionTime, patternPath, deviceId } = req.body;
        const safeDeviceId = typeof deviceId === 'string' ? deviceId.slice(0, 100) : 'UNKNOWN_DEVICE';

        if (typeof sessionPin !== 'string' || !/^\d{6}$/.test(sessionPin)) {
            return res.status(400).json({ error: "كود الجلسة غير صالح" });
        }
        if (typeof submissionTime !== 'number' || submissionTime <= 0 || submissionTime > Date.now() + 5000) {
            return res.status(400).json({ error: "وقت التسجيل غير صالح" });
        }

        const attemptRef = db.collection('rate_limits').doc(`autosync_${studentUID}`);
        const attemptSnap = await attemptRef.get();
        let attempts = 0;
        if (attemptSnap.exists) {
            const data = attemptSnap.data();
            const expired = (Date.now() - (data.updatedAt?.toMillis() || 0)) > 60_000;
            if (expired) await attemptRef.delete();
            else attempts = data.attempts || 0;
        }
        if (attempts >= 5) {
            return res.status(429).json({ error: "⛔ تجاوزت عدد المحاولات، انتظر دقيقة" });
        }

        const studentSnap = await db.collection('user_registrations').doc(studentUID).get();
        if (!studentSnap.exists) return res.status(404).json({ error: "بيانات الطالب غير موجودة" });
        const sData = studentSnap.data();
        const info = sData.registrationInfo || sData;
        const studentID = String(info.studentID || sData.studentID || '').trim();
        if (!studentID) return res.status(403).json({ error: "رقم جامعي غير موثق" });

        const codeSnap = await db.collection('issued_codes_logs').doc(sessionPin).get();
        if (!codeSnap.exists) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(404).json({ error: "❌ كود غير صحيح" });
        }
        const codeData = codeSnap.data();
        const doctorUID = codeData.doctorId;
        if (!doctorUID) return res.status(500).json({ error: "بيانات الجلسة تالفة" });

        if (codeData.allowOffline === false) {
            return res.status(403).json({ error: "❌ عذراً، قام محاضر المادة بإيقاف ميزة التسجيل الأوفلاين لهذه الجلسة." });
        }

        const sessionPassword = codeData.offlinePattern || null;
        if (sessionPassword) {
            if (!Array.isArray(patternPath) || patternPath.length < 3) {
                await attemptRef.set({
                    attempts: admin.firestore.FieldValue.increment(1),
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                }, { merge: true });
                return res.status(403).json({ error: "❌ النمط مطلوب" });
            }

            const serverPass = JSON.parse(sessionPassword);
            let isMatch = false;
            if (serverPass.mapping) {
                const mappedStudentPath = patternPath.map(idx => serverPass.mapping[idx]);
                isMatch = JSON.stringify(mappedStudentPath) === JSON.stringify(serverPass.path);
            } else {
                isMatch = JSON.stringify(patternPath) === JSON.stringify(serverPass.path);
            }

            if (!isMatch) {
                await attemptRef.set({
                    attempts: admin.firestore.FieldValue.increment(1),
                    updatedAt: admin.firestore.FieldValue.serverTimestamp()
                }, { merge: true });
                return res.status(403).json({ error: "❌ النمط غير صحيح" });
            }
        }

        const college = /^[A-Za-z0-9_]+$/.test(codeData.college || '') ? codeData.college : "NURS";
        const rawSubject = (codeData.subject || "General").toString();

        const openedAtMs = codeData.openedAt?.toMillis ? codeData.openedAt.toMillis() : Number(codeData.openedAt) || 0;
        const OFFLINE_WINDOW_MS = 25_000;
        const LOOSE_DRIFT = 4000;
        if (submissionTime < (openedAtMs - LOOSE_DRIFT) || submissionTime > (openedAtMs + OFFLINE_WINDOW_MS + LOOSE_DRIFT)) {
            await attemptRef.set({
                attempts: admin.firestore.FieldValue.increment(1),
                updatedAt: admin.firestore.FieldValue.serverTimestamp()
            }, { merge: true });
            return res.status(403).json({ error: "❌ خارج نافذة التسجيل المسموحة" });
        }

        const sessionSnap = await db.collection('active_sessions').doc(doctorUID).get();
        const sessionData = sessionSnap.exists ? sessionSnap.data() : {};
        const isStaleLive = sessionData.isActive === true && sessionData.sessionCode !== sessionPin;
        const isLive = sessionData.isActive === true && sessionData.sessionCode === sessionPin;

        if (isStaleLive) {
            return res.status(410).json({ error: "❌ انتهت صلاحية هذا الكود — تم إصدار كود جديد للجلسة" });
        }

        const { dateStr: fixedDateStr, timeStr: finalTimeStr } = getEgyptTimeInfo(submissionTime);
        const safeDateID = fixedDateStr.replace(/\//g, '-');
        const cleanSubKey = rawSubject.trim().replace(/\s+/g, '_').replace(/[^\w\u0600-\u06FF]/g, '');
        const recID = `${studentID}_${safeDateID}_${cleanSubKey}`;

        const basePayload = {
            id: studentID, sessionPin, name: info.fullName || sData.fullName || "Student",
            subject: rawSubject, college, hall: codeData.hall || "Hall", group: info.group || "GENERAL",
            date: fixedDateStr, time_str: finalTimeStr,
            timestamp: admin.firestore.Timestamp.fromMillis(submissionTime),
            status: "ATTENDED", doctorUID, doctorName: codeData.doctorName || "Doctor",
            isOfflineSync: true, feedback_status: "pending", feedback_rating: 0,
        };

        const batch = db.batch();

        if (isLive) {
            const participantRef = db.collection('active_sessions').doc(doctorUID).collection('participants').doc(studentUID);
            const participantSnap = await participantRef.get();
            const preservedSegmentCount = participantSnap.exists ? (participantSnap.data().segment_count || 1) : 1;

            batch.set(db.collection(`attendance_${college}`).doc(recID), { ...basePayload, notes: "منضبط (أوفلاين - أثناء الجلسة)" });
            batch.set(participantRef, {
                id: studentID, uid: studentUID, name: basePayload.name, status: "active",
                timestamp: admin.firestore.FieldValue.serverTimestamp(), isOfflineSync: true,
                submissionTime, segment_count: preservedSegmentCount
            });
            batch.set(db.collection('offline_attendance_log').doc(recID), {
                studentID, sessionPin, submissionTime, studentUID, deviceId: safeDeviceId,
                syncTimestamp: admin.firestore.FieldValue.serverTimestamp(), syncStatus: "SUCCESS_LIVE_UNIFIED_V1"
            });
        } else {
            batch.set(db.collection(`attendance_${college}`).doc(recID), { ...basePayload, notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)", isPostSession: true });
            batch.set(db.collection('offline_attendance_log').doc(recID), {
                studentID, sessionPin, submissionTime, studentUID, deviceId: safeDeviceId,
                syncTimestamp: admin.firestore.FieldValue.serverTimestamp(), syncStatus: "SUCCESS_POST_SESSION_UNIFIED_V1"
            });
            batch.set(db.collection('student_stats').doc(studentUID), {
                [`attended.${cleanSubKey}`]: admin.firestore.FieldValue.increment(1),
                last_attendance: admin.firestore.FieldValue.serverTimestamp(),
                fullName: basePayload.name, studentID, group: basePayload.group, college
            }, { merge: true });
            batch.set(db.collection('user_registrations').doc(studentUID), {
                pendingFeedback: {
                    attendanceDocId: recID, subject: rawSubject,
                    doctorName: codeData.doctorName || "Doctor",
                    createdAt: admin.firestore.FieldValue.serverTimestamp()
                }
            }, { merge: true });
        }

        await Promise.all([batch.commit(), attemptRef.delete().catch(() => { })]);

        console.log(`✅ Unified Sync | Student: ${studentID} | Mode: ${isLive ? 'live' : 'post-session'} | PIN: ${sessionPin}`);

        if (!isLive) {
            try {
                const { error: supErr } = await supabase
                    .from('attendance_logs')
                    .upsert([{
                        student_id: studentID,
                        student_name: basePayload.name,
                        subject_name: rawSubject,
                        college: college,
                        hall: codeData.hall || "",
                        target_group: basePayload.group,
                        sis_code: codeData.sisCode || "",
                        session_date: fixedDateStr,
                        attendance_time: finalTimeStr,
                        status: "ATTENDED",
                        is_unruly: false,
                        is_uniform_violation: false,
                        notes: "منضبط (أوفلاين - بعد إغلاق الجلسة)",
                        doctor_uid: doctorUID,
                        doctor_name: codeData.doctorName || "Doctor",
                        is_recovered: false,
                        feedback_status: "pending",
                        feedback_rating: 0,
                        segment_count: 1,
                        is_offline_sync: true,
                        level: info.level || "-",
                        group_name: basePayload.group,
                        is_suspicious: false,
                        trap_is_in_range: null,
                        trap_is_device_match: null,
                        trap_gps_success: null,
                        trap_distance_km: null,
                    }], {
                        onConflict: 'student_id,subject_name,session_date,doctor_uid'
                    });

                if (supErr) console.error("❌ Supabase sync error (post-session offline):", supErr);
                else console.log(`✅ Supabase synced (post-session offline) | Student: ${studentID} | PIN: ${sessionPin}`);
            } catch (supEx) {
                console.error("❌ Supabase exception (post-session offline):", supEx.message);
            }
        }

        res.status(200).json({ success: true, recID, mode: isLive ? 'live' : 'post-session', doctorUID });

    } catch (error) {
        console.error("❌ syncOfflineAttendance Error:", error);
        res.status(500).json({ error: "خطأ في السيرفر، حاول مجدداً" });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🛡️ Server Running Port ${PORT}`));

module.exports = app;
