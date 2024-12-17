const express = require("express");
const { DynamoDBClient } = require("@aws-sdk/client-dynamodb");
const { SNSClient } = require("@aws-sdk/client-sns");
const { DynamoDBDocumentClient, QueryCommand, TransactWriteCommand, PutCommand, ScanCommand } = require("@aws-sdk/lib-dynamodb");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid"); // 고유 ID 생성을 위해 사용
require("dotenv").config(); // .env 파일 로드

const app = express();
app.use(express.json());

const port = 3000;

// DynamoDB 클라이언트 초기화
const dynamoDBClient = new DynamoDBClient({
    region: process.env.AWS_REGION, // 환경 변수에서 리전 가져오기
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});
const dynamoDB = DynamoDBDocumentClient.from(dynamoDBClient);

// AWS SNS 클라이언트 설정
const snsClient = new SNSClient({
    region: process.env.AWS_REGION,
    credentials: {
        accessKeyId: process.env.AWS_ACCESS_KEY_ID,
        secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    },
});

// JWT 비밀 키
const JWT_SECRET = process.env.JWT_SECRET || "your_secret_key"; // .env에서 불러오거나 기본값 설정

// 1. 회원가입
app.post("/register", async (req, res) => {
    const { email, password, name } = req.body;

    if (!email || !password || !name) {
        return res.status(400).json({ error: "Email, password, and name are required." });
    }

    try {
        // 비밀번호 해싱
        const hashedPassword = await bcrypt.hash(password, 10); // 10은 saltRounds

        // 사용자 ID 생성
        const userId = uuidv4();

        // 현재 시간 생성
        const timestamp = new Date().toISOString();

        // DynamoDB에 사용자 저장
        const params = {
            TableName: "Users",
            Item: {
                userId,                // 고유 사용자 ID
                email,                 // 사용자 이메일
                passwordHash: hashedPassword, // 해싱된 비밀번호
                name,                  // 사용자 이름
                createdAt: timestamp,  // 계정 생성 시간
                updatedAt: timestamp,  // 계정 업데이트 시간
            },
        };

        await dynamoDB.send(new PutCommand(params));

        res.status(201).json({ message: "User registered successfully." });
    } catch (error) {
        console.error("Error during registration:", error);

        // DynamoDB 충돌 처리 (중복 이메일 처리)
        if (error.name === "ConditionalCheckFailedException") {
            return res.status(409).json({ error: "Email is already registered." });
        }

        res.status(500).json({ error: "Internal server error." });
    }
});

// 2. 사용자 로그인 (access_token 생성)
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: "Email and password are required." });
    }

    try {
        // 사용자 검색
        const params = {
            TableName: "Users",
            IndexName: "email-index", // 이메일 인덱스가 설정되어 있어야 합니다.
            KeyConditionExpression: "email = :email",
            ExpressionAttributeValues: {
                ":email": email,
            },
        };

        const result = await dynamoDB.send(new QueryCommand(params));
        const user = result.Items?.[0];

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // 비밀번호 검증
        const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
        if (!isPasswordValid) {
            return res.status(401).json({ error: "Invalid password." });
        }

        // JWT 생성
        const token = jwt.sign(
            { userId: user.userId, email: user.email }, // email 추가
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        // 성공 응답
        res.status(200).json({ accessToken: token });
    } catch (error) {
        console.error("Error during login:", error);
        res.status(500).json({ error: "Internal server error." });
    }
});

// 3. 계좌 추가 API
app.post("/accounts", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; // Bearer 토큰 형식

    if (!token) {
        return res.status(401).json({ error: "Access token is required." });
    }

    try {
        // 토큰 검증
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;

        // 요청 본문에서 계좌 정보 추출
        const { accountName, balance, currency, accountNumber } = req.body;

        if (!accountName || balance == null || !currency || !accountNumber) {
            return res.status(400).json({ error: "Account name, balance, currency, and account number are required." });
        }

        // 계좌번호가 중복되지 않는지 확인
        const checkParams = {
            TableName: "Accounts",
            IndexName: "accountNumber-index",
            KeyConditionExpression: "accountNumber = :accountNumber",
            ExpressionAttributeValues: {
                ":accountNumber": accountNumber,
            },
        };

        const checkResult = await dynamoDB.send(new QueryCommand(checkParams));
        if (checkResult.Items.length > 0) {
            return res.status(400).json({ error: "Account number already exists." });
        }

        // 계좌 ID 생성
        const accountId = uuidv4();
        const timestamp = new Date().toISOString();

        // DynamoDB에 계좌 추가
        const params = {
            TableName: "Accounts",
            Item: {
                userId,                // 사용자 ID (Partition Key)
                accountId,             // 계좌 ID (Sort Key)
                accountNumber,         // 계좌 번호 (고유값)
                accountName,           // 계좌 이름
                balance: parseFloat(balance), // 계좌 잔액
                currency,              // 통화
                createdAt: timestamp,  // 계좌 생성 시간
                updatedAt: timestamp,  // 계좌 업데이트 시간
            },
        };

        await dynamoDB.send(new PutCommand(params));

        res.status(201).json({ message: "Account added successfully.", accountId, accountNumber });
    } catch (error) {
        console.error("Error adding account:", error);

        if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Invalid or expired token." });
        }

        res.status(500).json({ error: "Internal server error." });
    }
});

// 4. 사용자의 계좌 상황 조회
app.get("/accounts", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; // Bearer 토큰 형식

    if (!token) {
        return res.status(401).json({ error: "Access token is required." });
    }

    try {
        // 토큰 검증
        const decoded = jwt.verify(token, JWT_SECRET);
        const userId = decoded.userId;

        // DynamoDB에서 계좌 데이터 조회
        const params = {
            TableName: "Accounts",
            KeyConditionExpression: "userId = :userId",
            ExpressionAttributeValues: {
                ":userId": userId,
            },
        };

        const result = await dynamoDB.send(new QueryCommand(params));
        const accounts = result.Items || [];

        res.status(200).json({ accounts });
    } catch (error) {
        console.error("Error fetching accounts:", error);

        if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Invalid or expired token." });
        }

        res.status(500).json({ error: "Internal server error." });
    }
});

// 송금하기 API
app.post("/transfer", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; // JWT 토큰 추출

    if (!token) {
        return res.status(401).json({ error: "Access token is required." });
    }

    const { senderAccountId, recipientAccountNumber, amount } = req.body;

    if (!senderAccountId || !recipientAccountNumber || amount == null) {
        return res.status(400).json({ error: "Sender account ID, recipient account number, and amount are required." });
    }

    if (amount <= 0) {
        return res.status(400).json({ error: "Transfer amount must be greater than zero." });
    }

    try {
        // 1. JWT 검증 및 email 추출
        const decoded = jwt.verify(token, JWT_SECRET);
        const email = decoded.email;

        // 2. 출금 계좌 확인
        const senderParams = {
            TableName: "Accounts",
            KeyConditionExpression: "userId = :userId AND accountId = :accountId",
            ExpressionAttributeValues: {
                ":userId": decoded.userId,
                ":accountId": senderAccountId,
            },
        };

        const senderResult = await dynamoDB.send(new QueryCommand(senderParams));
        const senderAccount = senderResult.Items?.[0];

        if (!senderAccount) {
            return res.status(404).json({ error: "Sender account not found." });
        }

        if (senderAccount.balance < amount) {
            return res.status(400).json({ error: "Insufficient balance." });
        }

        // 3. 수취 계좌 확인
        const recipientParams = {
            TableName: "Accounts",
            IndexName: "accountNumber-index",
            KeyConditionExpression: "accountNumber = :accountNumber",
            ExpressionAttributeValues: {
                ":accountNumber": recipientAccountNumber,
            },
        };

        const recipientResult = await dynamoDB.send(new QueryCommand(recipientParams));
        const recipientAccount = recipientResult.Items?.[0];

        if (!recipientAccount) {
            return res.status(404).json({ error: "Recipient account not found." });
        }

        // 4. 송금 실행 (트랜잭션)
        const newSenderBalance = senderAccount.balance - amount;
        const newRecipientBalance = recipientAccount.balance + amount;

        const transactionParams = {
            TransactItems: [
                {
                    Update: {
                        TableName: "Accounts",
                        Key: { userId: senderAccount.userId, accountId: senderAccount.accountId },
                        UpdateExpression: "SET balance = :newBalance, updatedAt = :updatedAt",
                        ConditionExpression: "balance >= :amount",
                        ExpressionAttributeValues: {
                            ":newBalance": newSenderBalance,
                            ":updatedAt": new Date().toISOString(),
                            ":amount": amount,
                        },
                    },
                },
                {
                    Update: {
                        TableName: "Accounts",
                        Key: { userId: recipientAccount.userId, accountId: recipientAccount.accountId },
                        UpdateExpression: "SET balance = :newBalance, updatedAt = :updatedAt",
                        ExpressionAttributeValues: {
                            ":newBalance": newRecipientBalance,
                            ":updatedAt": new Date().toISOString(),
                        },
                    },
                },
            ],
        };

        await dynamoDBClient.send(new TransactWriteCommand(transactionParams));

        // 5. 송금 정보 저장
        const transactionId = uuidv4();
        const timestamp = new Date().toISOString();

        const transactionLogParams = {
            TableName: "Transactions",
            Item: {
                transactionId: transactionId,
                senderAccountId: senderAccount.accountId,
                recipientAccountId: recipientAccount.accountId,
                accountNumber: senderAccount.accountNumber,
                amount: amount,
                timestamp: timestamp,
                status: "SUCCESS",
            },
        };

        await dynamoDB.send(new PutCommand(transactionLogParams));

        res.status(200).json({
            message: "Transfer successful.",
            transactionId: transactionId,
            senderAccountId: senderAccount.accountId,
            recipientAccountNumber: recipientAccountNumber,
            amount: amount,
        });
    } catch (error) {
        console.error("Error during transfer:", error);
        res.status(500).json({ error: "Internal server error." });
    }
});

// 계좌 송금 정보 조회
app.get("/transactions/:accountNumber", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; // JWT 토큰 추출

    if (!token) {
        return res.status(401).json({ error: "Access token is required." });
    }

    const { accountNumber } = req.params;

    if (!accountNumber) {
        return res.status(400).json({ error: "Account number is required." });
    }

    try {
        // JWT 검증
        jwt.verify(token, JWT_SECRET);

        // 송금 내역과 수취 내역을 조회 (Scan 사용)
        const scanParams = {
            TableName: "Transactions",
            FilterExpression: "accountNumber = :accountNumber OR recipientAccountId = :accountNumber",
            ExpressionAttributeValues: {
                ":accountNumber": accountNumber,
            },
        };

        const scanResult = await dynamoDB.send(new ScanCommand(scanParams));

        // 응답 반환
        res.status(200).json({
            transactions: scanResult.Items || [],
        });
    } catch (error) {
        console.error("Error fetching transactions:", error);

        if (error.name === "JsonWebTokenError" || error.name === "TokenExpiredError") {
            return res.status(401).json({ error: "Invalid or expired token." });
        }

        res.status(500).json({ error: "Internal server error." });
    }
});

// 서버 시작
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});