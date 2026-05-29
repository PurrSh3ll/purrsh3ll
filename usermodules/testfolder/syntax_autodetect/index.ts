interface User {
    id: number;
    name: string;
    email: string;
    role: "admin" | "user" | "guest";
}

type ApiResponse<T> = {
    data: T;
    status: number;
    message: string;
};

async function fetchUsers(url: string): Promise<ApiResponse<User[]>> {
    const response = await fetch(url);
    if (!response.ok) {
        throw new Error(`HTTP error: ${response.status}`);
    }
    return response.json() as Promise<ApiResponse<User[]>>;
}

function filterByRole(users: User[], role: User["role"]): User[] {
    return users.filter(u => u.role === role);
}

class UserService {
    private cache = new Map<number, User>();

    constructor(private readonly baseUrl: string) {}

    async getUser(id: number): Promise<User | undefined> {
        if (this.cache.has(id)) {
            return this.cache.get(id);
        }
        const result = await fetchUsers(`${this.baseUrl}/users/${id}`);
        const user = result.data[0];
        if (user) this.cache.set(id, user);
        return user;
    }

    clearCache(): void {
        this.cache.clear();
    }
}

export { UserService, fetchUsers, filterByRole };
export type { User, ApiResponse };
