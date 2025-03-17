const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

// 数据库连接池
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME1,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});
const pool2 = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME2,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '未提供认证令牌' });
  }

  try {
    // 1. 验证 Token 是否过期
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    // 2. 查询数据库，确保 Token 未被清除（如用户主动退出）
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE token = ?',
      [token]
    );

    if (rows.length === 0) {
      return res.status(403).json({ error: '认证令牌无效或已过期' });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: '认证令牌无效或已过期' });
  }
};

// 后端新增接口：验证 Token 有效性
app.get('/api/validate-token', authenticateToken, (req, res) => {
  res.json({ valid: true });
});

// 注册接口
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    
    const [result] = await pool.execute(
      'INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
      [username, email, hashedPassword]
    );
    
    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 登录接口(网页登录)
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const [rows] = await pool.execute(
      'SELECT * FROM users WHERE username = ?',
      [username]
    );
    
    if (rows.length === 0) {
      return res.status(401).json({ error: '用户不存在' });
    }
    
    const user = rows[0];
    const passwordValid = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordValid) {
      return res.status(401).json({ error: '密码错误' });
    }
    
    // 生成 Token
    const token = jwt.sign(
      { userId: user.id, username: user.username },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // 打印 SQL 和参数
    console.log('执行 SQL:', 'UPDATE users SET token = ? WHERE id = ?');
    console.log('参数:', [token, user.id]);

    // 更新 Token
    const [updateResult] = await pool.execute(
      'UPDATE users SET token = ? WHERE id = ?',
      [token, user.id]
    );

    // 立即查询数据库验证
    const [verifyRows] = await pool.execute(
      'SELECT token FROM users WHERE id = ?',
      [user.id]
    );
    console.log('验证数据库 Token:', verifyRows[0].token); // 打印实际存储的 Token
    res.json({ 
      token,
      username: user.username,
      userId: user.id,
      expiresIn: 3600 // 明确返回有效期
    });
  } catch (error) {
    console.error('登录错误:',  error.message);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

//退出登录接口：删除 users 表中的 token 字段
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;

    // 删除 Token
    await pool.execute(
      'UPDATE users SET token = NULL WHERE id = ?',
      [userId]
    );

    res.json({ message: '退出登录成功' });
  } catch (error) {
    console.error('退出登录错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 设备配网(返回topic)
app.post('/api/iot/get_topic', async (req, res) => {
  try {
    const { username, password } = req.body;

    // 验证用户凭证
    const [users] = await pool.execute(
      'SELECT id, password_hash, created_at FROM users WHERE username = ?',
      [username]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: '用户不存在' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: '密码错误' });
    }

    // 生成ID部分（7位十六进制）
    const idNumber = user.id + 6777216;
    const idHex = idNumber.toString(16).toUpperCase().padStart(7, '0');

    // 生成日期部分（3位十六进制）
    const datePart = user.created_at.toISOString().split('T')[0]; // 处理时间格式
    const [year, month, day] = datePart.split('-').map(Number);
    const dateSum = year + month + day;
    const dateHex = dateSum.toString(16).toUpperCase().padStart(3, '0');

    // 组合完整topic
    const topic = `${idHex}${dateHex}`;

    res.json({
      topic, // 返回topic
    });
  } catch (error) {
    console.error('配网错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});


/*设备在线下线检测，逻辑：订阅主题后，根据订阅主题获得用户id、与username，根据id和username为外键，添加设备Mac即客户端ID；因使用emqx转发，以绑定了users数据库，运行中错误只能是topic错误导致*/
// 订阅主题后响应内容
app.post('/api/iot/online', async (req, res) => {
   try {
    const { topic, username, clientid } = req.body;
    
    // 提取用户ID部分并转换
    const hexUserId = topic.substring(0, 7);
    const userIdDecimal = parseInt(hexUserId, 16);
    const userId = userIdDecimal - 6777216;

    if(clientid === '11111111111111111')
      return res.status(200).json({ message: '服务器端上线' });

    // 查询是否已记录
    const [existing] = await pool2.execute(
      'SELECT mac_address FROM devices WHERE mac_address = ?',
      [clientid]
    );

    // 判断应该新增或修改记录
    if (existing.length === 0) {
      await pool2.execute(
        'INSERT INTO devices (id, username, mac_address, is_online) VALUES (?, ?, ?, 1)',
        [userId, username, clientid]
      );
    } else {
      await pool2.execute(
        'UPDATE devices SET is_online = 1 WHERE mac_address = ?',
        [clientid]
      );
    }

    res.status(200).json({ message: '设备上线状态更新成功' });
  } catch (error) {
    if (error.code === 'ER_NO_REFERENCED_ROW_2') {
      console.error('topic主题错误');
      return res.status(400).json({ error: 'topic主题错误' });
    }
    else
      console.error('设备订阅保存错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

// 客户端连接断开触发
app.post('/api/iot/unonline', async (req, res) => {
   try {
    const { clientid, username } = req.body;

    if (clientid === '11111111111111111') {
      return res.status(200).json({ message: '服务器端下线' });
    }

    // 更新设备状态
    const [result] = await pool2.execute(
      'UPDATE devices SET is_online = 0 WHERE mac_address = ?',
      [clientid]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: '设备未找到或用户不匹配' });
    }

    res.status(200).json({ message: '设备离线状态更新成功' });
  } catch (error) {
    console.error('客户端断开记录错误:', error);
    res.status(500).json({ error: '服务器内部错误' });
  }
});

app.post('/api/iot/get', async (req, res) => {
  try {
    const { topic, clientid, username, payload } = req.body;
    const receiveTime = new Date();

    if (clientid === '11111111111111111') {
      return console.log('服务器端下发消息');
    }

    // 数据清洗逻辑
    let rawData = payload;
    
    // 如果是字符串类型才需要处理
    if (typeof rawData === 'string') {
      // 找到第一个JSON开始位置
      const jsonStart = rawData.indexOf('{');
      // 找到最后一个JSON结束位置
      const jsonEnd = rawData.lastIndexOf('}') + 1;
      
      if (jsonStart !== -1 && jsonEnd !== -1) {
        rawData = rawData.slice(jsonStart, jsonEnd);
      }
    }

    // 直接解析原始数据（不提取msg）
    const payloadData = typeof rawData === 'string' 
      ? JSON.parse(rawData)
      : rawData;

    // 完整保存有效JSON
    await pool2.execute(
      'INSERT INTO gather (time, theme, msg, mac_address) VALUES (?, ?, ?, ?)',
      [receiveTime, topic, JSON.stringify(payloadData), clientid]
    );

    console.log(`数据已保存: ${clientid} - ${topic}`);
    res.status(200).json({ message: '数据接收成功' });
    
  } catch (error) {
    console.error('数据处理错误:', error);
    res.status(500).json({ 
      error: '数据处理失败',
      details: {
        message: error.message,
        stack: error.stack
      }
    });
  }
});

// 消息已投递触发(服务器下发完成触发，验证是否被硬件客户端接收(topic被订阅才会触发))
app.post('/api/iot/set', async (req, res) => {
  try {
    const { from_clientid } = req.body;
    if(from_clientid === '11111111111111111')
    {
    	console.log('测试: ',req.body);
    	res.status(200).json({ message: '数据接收成功' });
    }
    else
    	return console.log('非服务器下发数据');
  } catch (error) {
    console.error('硬件端数据接收错误:', error);
    res.status(500).json({ error: '数据下发失败' });
  }
});

// 获取现有设备的key与对应value
app.post('/api/iot/get_keyvalue', async (req, res) => {
  try {
    const { userId } = req.body;
    // 获取用户所有mac地址
    const [devices] = await pool2.query(
      'SELECT mac_address FROM devices WHERE id = ?', 
      [userId]
    ); 
    const result = {};
    // 遍历每个设备
    for (const device of devices) {
      const mac = device.mac_address;
      // 查询最新msg数据
      const [gatherData] = await pool2.query(
        `SELECT msg 
         FROM gather 
         WHERE mac_address = ? 
         ORDER BY time DESC 
         LIMIT 1`,
        [mac]
      );  
      if (gatherData.length > 0) {
        // 解析JSON并统计
        try {
          console.log("gatherData[0].msg:", gatherData[0].msg);
          const msgObj = JSON.parse(gatherData[0].msg).msg;
          const keys = Object.keys(msgObj);
          
          result[mac] = {
            key_count: keys.length,
            key_details: keys.map(k => ({
              key: k, 
              value: msgObj[k]
            }))
          };
        } catch (e) {
          result[mac] = { error: "Invalid JSON format" };
        }
      }
    }
    res.json(result);
  } catch (error) {
    console.log(`错误: ${error.message}`);
    res.status(200).json({ message: '错误' });
  }
});

// 刷新设备信息：保存设备的原始 key
app.post('/api/iot/save_keys', authenticateToken , async (req, res) => {
  try {
    const { userId } = req.body;

    // 获取用户所有设备的 MAC 地址
    const [devices] = await pool2.query(
      'SELECT mac_address FROM devices WHERE id = ?',
      [userId]
    );

    // 遍历每个设备
    for (const device of devices) {
      const mac = device.mac_address;

      // 查询设备的最新 msg 数据
      const [gatherData] = await pool2.query(
        `SELECT msg 
         FROM gather 
         WHERE mac_address = ? 
         ORDER BY time DESC 
         LIMIT 1`,
        [mac]
      );

      if (gatherData.length > 0) {
        try {
          // 解析 msg 数据
          const msgObj = JSON.parse(gatherData[0].msg).msg;
          const keys = Object.keys(msgObj);

          // 获取已保存的 key_alias
          const [savedKeys] = await pool2.query(
            'SELECT mac_key, key_alias FROM device_key WHERE mac_address = ?',
            [mac]
          );

          const savedKeyMap = new Map(savedKeys.map((k) => [k.mac_key, k.key_alias]));

          // 将原始 key 保存到 device_key 表（只添加新的 key）
          for (const key of keys) {
            if (!savedKeyMap.has(key)) {
              await pool2.execute(
                `INSERT INTO device_key (mac_address, mac_key, key_alias)
                 VALUES (?, ?, ?)`,
                [mac, key, key] // 初始 key_alias 与 mac_key 相同
              );
            }
          }
        } catch (e) {
          console.error(`设备 ${mac} 的 msg 数据解析失败:`, e);
        }
      }
    }

    res.json({ message: '设备 key 已刷新' });
  } catch (error) {
    console.error('刷新设备 key 失败:', error);
    res.status(500).json({ error: '刷新设备 key 失败' });
  }
});

app.get('/api/iot/devices', authenticateToken, async (req, res) => {
  try {
    const userId = req.query.userId;

    // 获取设备列表
    const [devices] = await pool2.query(
      'SELECT mac_address, mac_alias, is_online FROM devices WHERE id = ?',
      [userId]
    );

    const result = {}; // 以 MAC 地址为键的对象

    // 获取每个设备的key别名及最新msg
    for (const device of devices) {
      // 获取设备的最新msg
      const [latestMsg] = await pool2.query(
        `SELECT msg 
         FROM gather 
         WHERE mac_address = ? 
         ORDER BY time DESC 
         LIMIT 1`,
        [device.mac_address]
      );

      // 获取设备的key别名
      const [keys] = await pool2.query(
        `SELECT mac_key, key_alias, device_type 
         FROM device_key 
         WHERE mac_address = ?`,
        [device.mac_address]
      );

      // 将设备数据组织为以 MAC 地址为键的对象
      result[device.mac_address] = {
        mac_alias: device.mac_alias,
        is_online: device.is_online,
        msg: latestMsg.length > 0 ? latestMsg[0].msg : null, // 设备的最新msg
        keys: keys, // 设备的key别名
      };

      // 打印设备数据
      console.log(`设备 ${device.mac_address} 的 keys:`, keys);
    }

    res.json(result);
  } catch (error) {
    console.error('获取设备失败:', error);
    res.status(500).json({ error: '获取设备失败' });
  }
});

// 保存设备别名
app.post('/api/iot/set_keyvalue', authenticateToken , async (req, res) => {
  try {
    const { mac_address, mac_alias, keys } = req.body;
    
    // 更新设备别名
    await pool2.execute(
      'UPDATE devices SET mac_alias = ? WHERE mac_address = ?',
      [mac_alias, mac_address]
    );

    // 更新key别名
    for (const { mac_key, key_alias ,device_type} of keys) {
      await pool2.execute(
        `INSERT INTO device_key (mac_address, mac_key, key_alias, device_type)
         VALUES (?, ?, ?,?)
         ON DUPLICATE KEY UPDATE key_alias = VALUES(key_alias),device_type = VALUES(device_type)`,  // 新增更新字段
        [mac_address, mac_key, key_alias,device_type || 1]
      );
    }

    res.json({ message: '保存成功' });
  } catch (error) {
    res.status(500).json({ error: '保存失败' });
  }
});


app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
