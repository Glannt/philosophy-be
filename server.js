import express from 'express';
import cors from 'cors';
import fs from 'fs';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json()); // nhận JSON từ frontend

// File lưu user
const USERS_FILE = './users.json';
// JWT secret
const JWT_SECRET = process.env.JWT_SECRET ?? 'default_secret_key';
// Gemini API
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;

const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

/** Đọc danh sách user từ file */
const readUsers = () => {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf-8'));
};

/** Ghi danh sách user vào file */
const writeUsers = (users) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

/** Tạo JWT token */
const createToken = (email) => {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: '1d' });
};

/** Xác thực JWT token */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

app.post('/', async (req, res) => {
  try {
    const { action, email, password, name, token, message } = req.body;
    let users = readUsers();

    switch (action) {
      // Đăng ký
      case 'signup': {
        if (!email || !password || !name)
          return res.json({ success: false, message: 'Thiếu thông tin.' });

        if (users.find((u) => u.email === email))
          return res.json({ success: false, message: 'Email đã tồn tại.' });

        const hashed = await bcrypt.hash(password, 10);
        users.push({ name, email, password: hashed });
        writeUsers(users);

        return res.json({ success: true });
      }

      // Đăng nhập
      case 'login': {
        const user = users.find((u) => u.email === email);
        if (!user)
          return res.json({
            success: false,
            message: 'Không tìm thấy tài khoản.',
          });

        const match = await bcrypt.compare(password, user.password);
        if (!match)
          return res.json({ success: false, message: 'Sai mật khẩu.' });

        const token = createToken(user.email);
        return res.json({
          success: true,
          token,
          name: user.name,
          email: user.email,
        });
      }

      // Xác thực token
      case 'verify': {
        const data = verifyToken(token);
        if (!data) return res.json({ success: false });

        const user = users.find((u) => u.email === data.email);
        if (!user) return res.json({ success: false });

        return res.json({ success: true, name: user.name, email: user.email });
      }

      // Logout
      case 'logout': {
        // JWT không lưu trạng thái, frontend tự xóa
        return res.json({ success: true });
      }

      // Chat với Gemini (không cần xác thực)
      case 'chat': {
        if (!message)
          return res.json({ success: false, message: 'Thiếu message.' });

        // Prompt chuyên sâu, biến AI thành triết gia kinh tế
        const fullMessage = `
Bạn là một triết gia kinh tế uyên thâm, chuyên về kinh tế chính trị và kinh tế thị trường hướng tới chủ nghĩa xã hội.
Nhiệm vụ của bạn là:
1. Chỉ trả lời về kinh tế thị trường hướng tới chủ nghĩa xã hội.
2. Giải thích các đặc trưng cơ bản, cơ chế vận hành, ưu – nhược điểm.
3. Minh họa bằng các ví dụ thực tiễn hoặc lý thuyết nổi bật.
4. Không đề cập đến chính trị, văn hóa hay vấn đề xã hội khác.
5. Trình bày một cách logic, sâu sắc và có góc nhìn triết học.

Câu hỏi của người dùng: "${message}"
`;

        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: [{ parts: [{ text: fullMessage }] }],
        });

        return res.json({ success: true, answer: response.text });
      }

      default:
        return res.json({ success: false, message: 'Action không hợp lệ.' });
    }
  } catch (err) {
    console.error('❌ Lỗi server:', err);
    res.status(500).json({ success: false, message: 'Lỗi server.' });
  }
});

// Chạy server
app.listen(process.env.PORT || 3000, () =>
  console.log(`✅ Server chạy tại http://localhost:${process.env.PORT || 3000}`)
);
