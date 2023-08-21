export interface JwtPayload {

    id: string;
    iat?: number;  //fecha de inicio
    exp?: number;  //fecha de exp

}