use type_permissions::And;
use type_permissions::Dispatch;
use type_permissions::PhantomToken;
use type_permissions::*;
use typed_perm_derive::Permissions;

#[derive(Permissions, Hash, Eq, PartialEq, Clone, Debug)]
enum Permissions {
    CanCallFunctionX,
    CanCallFunctionY,
}

fn fun_y<T: ?Sized + TCanCallFunctionY>(_: PhantomToken<T>) {
    println!("Hello world");
}

fn get_typed_perm<T: ?Sized + Dispatch<Permissions>>() -> PhantomToken<T> {
    unsafe { PhantomToken::new_unchecked() }
}

fn main() {
    println!("{:?}", CanCallFunctionX::dispatch());
}
