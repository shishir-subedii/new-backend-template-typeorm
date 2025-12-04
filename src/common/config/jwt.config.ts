export const jwtConfig = {
    accessSecret: process.env.JWT_ACCESS_SECRET as string,
    refreshSecret: process.env.JWT_REFRESH_SECRET as string,
    accessExpire: process.env.JWT_ACCESS_EXPIRE as string,
    refreshExpire: process.env.JWT_REFRESH_EXPIRE as string,
};
