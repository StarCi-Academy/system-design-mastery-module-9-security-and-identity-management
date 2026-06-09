import { Entity, Column, PrimaryGeneratedColumn } from "typeorm"

// Single demo entity — proves the Vault-sourced password opened a real DB connection.
@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id: number

    @Column()
    name: string
}
