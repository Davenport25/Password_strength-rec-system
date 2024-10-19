# fuzzy_logic_password.py

import string
import numpy as np
import skfuzzy as fuzz
from skfuzzy import control as ctrl
import random

# Generate universes
x_len = np.arange(0, 21, 1)
x_com = np.arange(0, 11, 1)
x_str = np.arange(0, 101, 1)

# Length MFs
len_vs = fuzz.trimf(x_len, [0, 0, 5])
len_s = fuzz.trimf(x_len, [0, 5, 10])
len_m = fuzz.trimf(x_len, [5, 10, 15])
len_l = fuzz.trimf(x_len, [10, 15, 20])
len_vl = fuzz.trimf(x_len, [15, 20, 20])

# Complexity MFs
com_vl = fuzz.trimf(x_com, [0, 2, 4])
com_l = fuzz.trimf(x_com, [2, 4, 6])
com_m = fuzz.trimf(x_com, [4, 6, 8])
com_h = fuzz.trimf(x_com, [6, 8, 10])
com_vh = fuzz.trimf(x_com, [8, 10, 10])

# Strength MFs
str_vw = fuzz.trimf(x_str, [0, 20, 40])
str_w = fuzz.trimf(x_str, [20, 40, 60])
str_m = fuzz.trimf(x_str, [40, 60, 80])
str_s = fuzz.trimf(x_str, [60, 80, 100])
str_vs = fuzz.trimf(x_str, [80, 100, 100])

length = ctrl.Antecedent(x_len, 'length')
complexity = ctrl.Antecedent(x_com, 'complexity')
strength = ctrl.Consequent(x_str, 'strength')

length.automf(names=['very_short', 'short', 'medium', 'long', 'very_long'])
complexity.automf(names=['very_low', 'low', 'medium', 'high', 'very_high'])

strength['very_weak'] = str_vw
strength['weak'] = str_w
strength['medium'] = str_m
strength['strong'] = str_s
strength['very_strong'] = str_vs

# Define the rules
rules = [
    ctrl.Rule(complexity['very_low'] | length['very_short'], strength['very_weak']),
    ctrl.Rule(complexity['low'] & length['short'], strength['weak']),
    ctrl.Rule(complexity['medium'] & length['medium'], strength['medium']),
    ctrl.Rule(complexity['high'] & length['long'], strength['strong']),
    ctrl.Rule(complexity['very_high'] & length['very_long'], strength['very_strong']),
]

# Control system creation and simulation
password_system = ctrl.ControlSystem(rules)
password_sim = ctrl.ControlSystemSimulation(password_system)

def determine_complexity(password):
    """Determine the complexity score of a password."""
    length = len(password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_special = any(c in string.punctuation for c in password)

    score = 0
    if length > 5:
        score += 2
    if has_lower:
        score += 2
    if has_upper:
        score += 2
    if has_digit:
        score += 2
    if has_special:
        score += 2

    if score <= 2:
        return 'very_low'
    elif score <= 5:
        return 'low'
    elif score <= 8:
        return 'medium'
    elif score <= 12:
        return 'high'
    else:
        return 'very_high'

def check_password_strength(password):
    """Check the strength of the password."""
    password_length = len(password)
    password_complexity = determine_complexity(password)
    complexity_mapping = {'very_low': 2, 'low': 4, 'medium': 6, 'high': 8, 'very_high': 10}

    password_sim.input['length'] = password_length
    password_sim.input['complexity'] = complexity_mapping[password_complexity]
    password_sim.compute()

    strength_score = password_sim.output['strength']

    strength_levels = {
        'very_weak': fuzz.interp_membership(x_str, str_vw, strength_score),
        'weak': fuzz.interp_membership(x_str, str_w, strength_score),
        'medium': fuzz.interp_membership(x_str, str_m, strength_score),
        'strong': fuzz.interp_membership(x_str, str_s, strength_score),
        'very_strong': fuzz.interp_membership(x_str, str_vs, strength_score)
    }

    max_strength = max(strength_levels, key=strength_levels.get)
    return max_strength, strength_score

def recommend_stronger_password(password):
    """Recommend a stronger password."""
    if len(password) < 8:
        password += ''.join(random.choices(string.ascii_letters + string.digits, k=(8 - len(password))))
    if not any(c.islower() for c in password):
        password += random.choice(string.ascii_lowercase)
    if not any(c.isupper() for c in password):
        password += random.choice(string.ascii_uppercase)
    if not any(c.isdigit() for c in password):
        password += random.choice(string.digits)
    if not any(c in string.punctuation for c in password):
        password += random.choice(string.punctuation)

    return ''.join(random.sample(password, len(password)))


def evaluate_password(password):
    if not password:
        return 0  # Or some default value

    length_value = len(password)
    complexity_value = 0
    complexity_value += any(c.islower() for c in password) * 2
    complexity_value += any(c.isupper() for c in password) * 2
    complexity_value += any(c.isdigit() for c in password) * 2
    complexity_value += any(c in '!@#$%^&*()_+[]{}|;:,.<>?/~`' for c in password) * 2

    complexity_value = min(complexity_value, 10)

    # Initialize the control system simulation
    strength_sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))
    strength_sim.input['length'] = length_value
    strength_sim.input['complexity'] = complexity_value
    strength_sim.compute()

    return strength_sim.output['strength']
