import express from "express";
import cors from "cors";
import fs from "fs";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.text({ type: "application/json" })); // vì frontend gửi Content-Type: text/plain

const USERS_FILE = "./users.json";
const JWT_SECRET = process.env.JWT_SECRET ?? "default_secret_key";

/**
 * Đọc danh sách user từ file JSON
 */
const readUsers = () => {
  if (!fs.existsSync(USERS_FILE)) return [];
  return JSON.parse(fs.readFileSync(USERS_FILE, "utf-8"));
};

/**
 * Ghi danh sách user vào file JSON
 */
const writeUsers = (users) => {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
};

/**
 * Tạo JWT token
 */
const createToken = (email) => {
  return jwt.sign({ email }, JWT_SECRET, { expiresIn: "1d" });
};

/**
 * Xác thực JWT token
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
};

/**
 * Endpoint chính xử lý các action (login, signup, verify, logout)
 */
app.post("/", async (req, res) => {
  try {
    const { action, email, password, name, token } = JSON.parse(req.body || "{}");
    let users = readUsers();

    switch (action) {
      case "signup": {
        if (!email || !password || !name)
          return res.json({ success: false, message: "Thiếu thông tin." });

        if (users.find((u) => u.email === email))
          return res.json({ success: false, message: "Email đã tồn tại." });

        const hashed = await bcrypt.hash(password, 10);
        users.push({ name, email, password: hashed });
        writeUsers(users);

        return res.json({ success: true });
      }

      case "login": {
        const user = users.find((u) => u.email === email);
        if (!user) return res.json({ success: false, message: "Không tìm thấy tài khoản." });

        const match = await bcrypt.compare(password, user.password);
        if (!match) return res.json({ success: false, message: "Sai mật khẩu." });

        const token = createToken(user.email);
        return res.json({
          success: true,
          token,
          name: user.name,
          email: user.email,
        });
      }

      case "verify": {
        const data = verifyToken(token);
        if (!data) return res.json({ success: false });

        const user = users.find((u) => u.email === data.email);
        if (!user) return res.json({ success: false });

        return res.json({ success: true, name: user.name, email: user.email });
      }

      case "logout": {
        // JWT không cần lưu trạng thái nên chỉ cần xoá ở frontend
        return res.json({ success: true });
      }

      default:
        return res.json({ success: false, message: "Action không hợp lệ." });
    }
  } catch (err) {
    console.error("❌ Lỗi server:", err);
    res.status(500).json({ success: false, message: "Lỗi server." });
  }
});

app.listen(process.env.PORT, () =>
  console.log(`✅ Server chạy tại http://localhost:${process.env.PORT}`)
);
