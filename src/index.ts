import { NextFunction, Request, Response } from "express";

const express = require("express");
const { PrismaClient } = require("@prisma/client");
const bcrypt =  require("bcrypt")
const jwt = require("jsonwebtoken");
import * as dotenv from 'dotenv';
import { google } from 'googleapis';

const app = express();
const PORT = 5000;
const prisma = new PrismaClient();

const oauth2Client = new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'http://localhost:5000/auth/google/callback'
)

const scopes = [
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile'
]

const authorizationUrl = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    include_granted_scopes: true
})

app.use(express.json());

interface UserData {
    id: string;
    name: string;
    address: string;
}

interface ValidationRequest extends Request {
    headers: {
        authorization: string
    },
    userData: UserData;
}

const accessValidation = (req: ValidationRequest, res: Response, next: NextFunction) => {
    const { authorization } = req.headers;

    if (!authorization) {
        return res.status(401).json({
            message: "Token diperlukan"
        })
    }

    const token = authorization.split(' ')[1];
    const secret = process.env.JWT_SECRET;

    try {
        const jwtDecode = jwt.verify(token, secret);

        if (typeof jwtDecode !== "string") {
            req.userData = jwtDecode;
        }

    } catch (error) {
        return res.status(401).json({
            message: "Unauthorized"
        })
    }
    next();
}

// Google Login
app.get("/auth/google", (req: Request, res: Response) => {
    res.redirect(authorizationUrl)
})

// Google callback login
app.get("/auth/google/callback", async (req: Request, res: Response) => {
    const { code } = req.query;

    const { tokens } = await oauth2Client.getToken(code as string);

    oauth2Client.setCredentials(tokens);

    const oauth2 = google.oauth2({
        auth: oauth2Client,
        version: 'v2'
    });

    const { data } = await oauth2.userinfo.get();

    if (!data.email || !data.name) {
        return res.json({
            data: data
        })
    };

    let user = await prisma.users.findUnique({
        where: {
            email: data.email
        }
    });

    if (!user) {
        user = await prisma.users.create({
            data: {
                name: data.name,
                email: data.email,
                address: "-"
            }
        })
    };

    const payload = {
        id: user.id,
        name: user.name,
        address: user.address
    };
    
    const secret = process.env.JWT_SECRET!;
    const expiresIn = 60 * 60 * 1;

    const token = jwt.sign(payload, secret, { expiresIn: expiresIn});

    // return res.redirect("")

    return res.json({
        data: {
            id: user.id,
            name: user.name,
            address: user.address
        },
        token: token
    });
});

// REGISTER
app.use("/register", async (req: any, res: any) => {
    const { name, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await prisma.users.create({
        data: {
            name,
            email,
            password: hashedPassword,
        }
    });

    res.json({
        data: result,
        message: "use created"
    })
});

// LOGIN
app.use("/login", async (req: any, res: any) => {
    const { email, password } = req.body;

    const user = await prisma.users.findUnique({
        where: {
            email: email
        }
    });

    if (!user) {
        return res.status(404).json({
            message: "User not found"
        })
    };

    if (!user.password) {
        return res.status(404).json({
            message: "Password not set"
        })
    }

    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (isPasswordValid) {
        const payload = {
            id: user.id,
            name: user.name,
            address: user.address
        }
        
        const secret = process.env.JWT_SECRET!;
        const expiresIn = 60 * 60 * 1;

        const token = jwt.sign(payload, secret, { expiresIn: expiresIn})

        return res.json({
            data: {
                id: user.id,
                name: user.name,
                address: user.address
            },
            token: token
        })
    } else {
        return res.status(403).json({
            message: "Wrong password"
        })
    }
})

// CREATE
app.post("/users", accessValidation, async (req: any, res: any) => {
    const { name, email, address } = req.body;
    const result = await prisma.users.create({
        data: {
            name: name,
            email: email,
            address:  address,

        }
    })

    res.json({
        message: "User created",
        data: result
    })
});

// READ
app.get("/users", accessValidation, async (req: any, res: any) => {
    const result = await prisma.users.findMany({
        select: {
            id: true,
            name: true,
            email: true,
            address: true,
        }
    });

    res.json({
        message: "USER list",
        data: result
    })
});

// UPDATE
app.patch("/users/:id", accessValidation, async (req: any, res: any) => {
    const { id } = req.params;
    const { name, email, address } = req.body;

    const result = await prisma.users.update({
        data: {
            name: name,
            email: email,
            address: address
        },
        where: {
            id: Number(id)
        }
    })
    res.json({
        message: `User ${id} updated`,
        data: result
    })
});

// DELETE
app.delete("/users/:id", accessValidation, async (req: any, res: any) => {
    const { id } = req.params;

    await prisma.users.delete({
        where: {
            id: Number(id)
        }
    })
    res.json({
        message: `User ${id} deleted`
    })
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
})