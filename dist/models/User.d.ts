export interface User {
    StudentID?: number;
    Name: string;
    Email: string;
    Password: string;
    RegistrationDate?: Date;
}
export interface AuthResponse {
    success: boolean;
    message: string;
    token?: string;
    user?: Omit<User, 'password'>;
}
