import { Request, Response, NextFunction } from 'express';
declare global {
    namespace Express {
        interface Request {
            user?: {
                id: number;
                email: string;
            };
        }
    }
}
export declare const verifyToken: (req: Request, res: Response, next: NextFunction) => void;
