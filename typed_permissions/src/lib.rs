//! This is a crate that can be used to easily generate traits so you can do something called type
//! level permission checking. The main idea is that you constrict some sensitive function to
//! require a token with a specific type signature. This way when you write a function which writes
//! to a database, you can constrict its type to for example `MustHaveDBWritePerms`. This in turn
//! uses the compiler itself to enforce permission checking, thus developers down the line using
//! that function will be forced to acquire a `PhantomToken` from some sort of claim, this can be a
//! JWT supplied by a client for example.
//!
//! This library contains a derive macro which converts a enum into a trait and a struct and
//! auto-impls several required traits so that the mechanism of generating `PhatomTokens` is as
//! easy as possible.
//!
//! # Example
//! ```
//! use type_permissions::Dispatch;
//! use type_permissions::PhantomToken;
//! use type_permissions::Permissions;
//!
//! /// These are our permissions that we want to derive.
//! #[derive(Permissions, Hash, Eq, PartialEq, Clone)]
//! enum Permissions {
//!     CanCallFunctionX,
//!     CanCallFunctionY,
//! }
//!
//! // These functions are now type constricted. In practice you want to use the `requires` proc
//! // macro.
//! fn function_x<T: ?Sized + TCanCallFunctionX>(_: PhantomToken<T>) {}
//! fn function_y<T: ?Sized + TCanCallFunctionY>(_: PhantomToken<T>) {}
//! fn function_xy<T: ?Sized + And<CanCallFunctionX, CanCallFunctionY>(_: PhantomToken<T>) {}
//! // No need to manually type constrict when using the `requires` macro
//! #[derive(Requires("CanCallFunctionX"))]
//! fn function_x_v2() {}
//!
//! // In practice this function should be some function which returns `Option<PhantomToken<T>>`
//! // and takes in a claim. Through the use of the `T::dispatch` function you get a set of
//! // identifiers which you can then compare with a list derived from the claim. If they match you
//! // `Some(..)` otherwise `None`.
//! // For the sake of simplicity we dont do that here however you get the idea.
//! fn get_typed_perm<T: ?Sized + Dispatch<Permissions>>() -> PhantomToken<T> {
//!     PhantomToken::new()
//! }
//!
//! fn main() {
//!     let token: PhantomToken<CanCallFunctionX> = get_typed_perm();
//!     function_x(token);
//!     // This wont compile because token doesnt have the `CanCallFunctionY` permission.
//!     // function_y(token);
//! }
//! ```
use std::cmp::Eq;
use std::collections::HashSet;
use std::hash::Hash;
use std::marker::PhantomData;

/// This is a trait which is auto applied to each generated permission struct. It is used for
/// signature dispatching. What I mean by that is that each permission struct must idenitify itself
/// so that deriving a `PhantomToken` from a JWT claim for example is as easy as possible.
pub trait Dispatch<T: Sized + Hash + Eq> {
    /// This is a required function which must return a `HashSet`, the set returned usually only
    /// contains one item of type `T`. Type `T` is usually the enum that derives `Permissions`.
    fn dispatch() -> HashSet<T>;
    /// To limit user implementation error, the `try_into_token` method takes in a set of roles and
    /// checks if `ops` is a superset of `Self::dispatch`, if it is then a `PhantomToken` is
    /// returned otherwise `None`. In theory this method does all role checking for you and you
    /// wont need to write your own code.
    fn try_into_token(ops: &HashSet<T>) -> Option<PhantomToken<Self>> {
        if Self::check_match(ops) {
            Some(unsafe { PhantomToken::new_unchecked() })
        } else {
            None
        }
    }

    /// Checks whether a ops set matches the dispatched set of `T`.
    fn check_match(ops: &HashSet<T>) -> bool {
        ops.is_superset(&Self::dispatch())
    }
}

/// Until variadics become a thing in rust, having functions require multiple permissions requires
/// the use of a trait that is able to sorta concat these types. Thus we use the `And` trait to
/// have functions require two permissions or more.
///
/// This trait can be infinetely stacked. In practice you wont really need to manually use this
/// trait unless youre debugging. One more caveat is that `T` and `U` cannot be swapped. Thus the
/// following code would be invalid.
/// ```no_compile rs
/// And<MyPerms, TypeA, TypeB> == And<MyPerms, TypeB, TypeA>
/// ```
/// What this means in practice is that when getting errors from the compiler double check that the
/// type signature of the token and the function are the same.
pub trait TAnd<Z: Sized + Hash + Eq, T: ?Sized + Dispatch<Z>, U: ?Sized + Dispatch<Z>> {}

/// When you want to build a `PhantomToken` you most likely want to pass `And` as a type parameter
/// instead of `TAnd` or `dyn TAnd`. When constricting the type requirement of some function, if
/// the top-level, parent type wrapping other needs to be `TAnd`, `T` and `U` need to be the struct
/// equivalent.
///
/// # Example
/// ``` no_compile
/// // instead of
/// fn test<T: And<And<Type1, Type2>, Type3>>() {}
/// // you write
/// fn test<T: TAnd<And<Type1, Type2>, Type3>>() {}
/// ```
pub struct And<Z: Sized + Hash + Eq, T: ?Sized + Dispatch<Z>, U: ?Sized + Dispatch<Z>> {
    _z: PhantomData<Z>,
    _t: PhantomData<T>,
    _u: PhantomData<U>,
}

impl<Z, T, U> TAnd<Z, T, U> for And<Z, T, U>
where
    Z: Sized + Hash + Eq + Clone,
    T: ?Sized + Dispatch<Z>,
    U: ?Sized + Dispatch<Z>,
{
}

impl<Z, T, U> Dispatch<Z> for And<Z, T, U>
where
    Z: Sized + Hash + Eq + Clone,
    T: ?Sized + Dispatch<Z>,
    U: ?Sized + Dispatch<Z>,
{
    fn dispatch() -> HashSet<Z> {
        T::dispatch().union(&U::dispatch()).cloned().collect()
    }
}

/// Logical or operation trait. Additionally see `And` and `TAnd`.
pub trait TOr<Z: Sized + Hash + Eq, T: ?Sized + Dispatch<Z>, U: ?Sized + Dispatch<Z>> {}
/// Logical or operation trait. Additionally see `And` and `TAnd`.
pub struct Or<Z: Sized + Hash + Eq, T: ?Sized + Dispatch<Z>, U: ?Sized + Dispatch<Z>> {
    _z: PhantomData<Z>,
    _t: PhantomData<T>,
    _u: PhantomData<U>,
}

impl<Z, T, U> TOr<Z, T, U> for Or<Z, T, U>
where
    Z: Sized + Hash + Eq + Clone,
    T: ?Sized + Dispatch<Z>,
    U: ?Sized + Dispatch<Z>,
{
}

impl<Z, T, U> Dispatch<Z> for Or<Z, T, U>
where
    Z: Sized + Hash + Eq + Clone,
    T: ?Sized + Dispatch<Z>,
    U: ?Sized + Dispatch<Z>,
{
    fn dispatch() -> HashSet<Z> {
        T::dispatch().union(&U::dispatch()).cloned().collect()
    }

    fn try_into_token(ops: &HashSet<Z>) -> Option<PhantomToken<Self>> {
        if T::check_match(ops) || U::check_match(ops) {
            Some(unsafe { PhantomToken::new_unchecked() })
        } else {
            None
        }
    }
}

/// A `PhantomToken` is essentially a token which is derived from some other token but is type
/// constricted. Functions that have typed permissions will have to take in a `PhantomToken<T>`
/// where `T` is the stacked typed permissions list.
pub struct PhantomToken<T: ?Sized> {
    _marker: PhantomData<T>,
}

impl<T: ?Sized> PhantomToken<T> {
    /// Method generates a new `PhantomToken`. This method should only be used for debugging. You
    /// most likely want [`Dispatch::try_into_token`].
    ///
    /// # Safety
    /// The method is safe in itself but it is logically unsafe as it can be used to essentially
    /// bypass the typed permissions for many functions.
    pub unsafe fn new_unchecked() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}
