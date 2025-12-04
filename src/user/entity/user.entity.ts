import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    UpdateDateColumn,
    OneToMany,
} from 'typeorm';

import { UserRole } from 'src/common/enums/auth-roles.enum';

@Entity('users')
export class User {
    @PrimaryGeneratedColumn('uuid')
    id: string;

    @Column({ type: 'varchar', unique: true })
    email: string;

    @Column({ type: 'varchar', nullable: true })
    name: string | null;

    @Column({ type: 'varchar', select: false, nullable: true })
    password: string | null;

    @Column({
        type: 'text',
        nullable: true,
        select: false,
    })
    refreshToken: string | null;

    @Column({ type: 'boolean', default: false })
    isVerified: boolean;

    @Column({ type: 'varchar', nullable: true })
    otp: string | null;

    @Column({ type: 'timestamptz', nullable: true })
    otpExpiry: Date | null;

    @Column({
        type: 'enum',
        enum: UserRole,
        default: UserRole.USER,
    })
    role: UserRole;

    @Column({ type: 'boolean', default: true })
    isActive: boolean;

    @CreateDateColumn({ type: 'timestamptz' })
    createdAt: Date;

    @UpdateDateColumn({ type: 'timestamptz' })
    updatedAt: Date;
}
