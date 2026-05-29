use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Clone)]
struct User {
    id: u64,
    name: String,
    email: String,
    active: bool,
}

impl fmt::Display for User {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "User({}, {})", self.id, self.name)
    }
}

fn find_active_users(users: &[User]) -> Vec<&User> {
    users.iter().filter(|u| u.active).collect()
}

fn group_by_domain(users: &[User]) -> HashMap<String, Vec<&User>> {
    let mut map: HashMap<String, Vec<&User>> = HashMap::new();
    for user in users {
        let domain = user.email.split('@').nth(1).unwrap_or("unknown");
        map.entry(domain.to_string()).or_default().push(user);
    }
    map
}

fn main() {
    let users = vec![
        User { id: 1, name: "Alice".into(), email: "alice@example.com".into(), active: true },
        User { id: 2, name: "Bob".into(),   email: "bob@other.org".into(),     active: false },
        User { id: 3, name: "Carol".into(), email: "carol@example.com".into(), active: true },
    ];

    let active = find_active_users(&users);
    println!("Active users: {}", active.len());
    for u in &active {
        println!("  {u}");
    }

    let by_domain = group_by_domain(&users);
    for (domain, members) in &by_domain {
        println!("{domain}: {} user(s)", members.len());
    }
}
