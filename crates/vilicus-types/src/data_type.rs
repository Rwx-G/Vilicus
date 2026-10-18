//! The data type set (D103): the only enumeration of data types in the code base. The provider
//! policy, the channel ceilings and each record's `data_types` read it from here (spine AD-6,
//! AD-9, AD-50).

closed_set! {
    /// One data type of the closed set of D103.
    pub enum DataType {
        /// Health data, children's included.
        Health => "health",
        /// Journal entries.
        Journal => "journal",
        /// Budget data.
        Budget => "budget",
        /// Meals.
        Meals => "meals",
        /// Meal plans.
        MealPlan => "meal_plan",
        /// Food stock.
        Stock => "stock",
        /// Shopping lists.
        ShoppingList => "shopping_list",
        /// Presence.
        Presence => "presence",
        /// Home device state.
        HomeState => "home_state",
        /// Alarm state.
        AlarmState => "alarm_state",
        /// Calendar data.
        Calendar => "calendar",
        /// Data about a child of the household.
        Child => "child",
        /// Raw mail.
        MailRaw => "mail_raw",
        /// Other household data.
        HouseholdOther => "household_other",
        /// Other personal data.
        PersonalOther => "personal_other",
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::test_support::{from_str, to_json};

    /// PRD FR-68 and D103, retyped on purpose: AC3 of Story 2.4 asks for a test that fails when a
    /// member is added to or removed from the set without this list changing with it.
    const D103_DATA_TYPES: [&str; 15] = [
        "health",
        "journal",
        "budget",
        "meals",
        "meal_plan",
        "stock",
        "shopping_list",
        "presence",
        "home_state",
        "alarm_state",
        "calendar",
        "child",
        "mail_raw",
        "household_other",
        "personal_other",
    ];

    #[test]
    fn data_type_set_is_exactly_d103() {
        let names: Vec<&str> = DataType::ALL
            .iter()
            .map(|data_type| data_type.as_str())
            .collect();
        assert_eq!(names, D103_DATA_TYPES);
        let distinct: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(distinct.len(), names.len(), "a name is used twice");
    }

    #[test]
    fn data_types_serialize_by_name() {
        for data_type in DataType::ALL {
            assert_eq!(to_json(data_type), Ok(format!("\"{data_type}\"")));
            assert_eq!(from_str::<DataType>(data_type.as_str()), Ok(*data_type));
        }
        for refused in ["Health", "meal-plan", "mealplan", "other", ""] {
            assert!(from_str::<DataType>(refused).is_err(), "{refused:?}");
        }
    }
}
