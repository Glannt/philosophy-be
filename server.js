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

app.options('/', (req, res) => {
  res.header('Access-Control-Allow-Origin', '*'); // hoặc thay bằng domain frontend
  res.header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.sendStatus(204);
});

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
Bạn là chuyên gia triết học kinh tế, tập trung vào kinh tế thị trường định hướng xã hội.

Yêu cầu:
1. Chỉ phân tích mô hình kinh tế thị trường định hướng xã hội.
2. Trình bày đặc trưng, cơ chế vận hành, ưu – nhược điểm.
3. Đưa ví dụ lý thuyết hoặc thực tiễn.
4. Không nhắc đến chính trị, văn hóa hay xã hội.
5. Diễn giải logic, súc tích, mang chiều sâu triết học.
6. Nếu người dùng chỉ chào hỏi, hãy chào lại ngắn gọn và chưa trả lời nội dung chính.

Câu hỏi: "${message}"
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
