"""
Wallet routes.
"""
from flask import Blueprint, render_template, redirect, session, flash, request, url_for
from services.wallet_service import get_wallet_balance, add_funds, get_wallet_transactions
import logging

logger = logging.getLogger(__name__)

wallet_bp = Blueprint('wallet', __name__)


def init_wallet_routes(mysql):
    """Initialize wallet routes with dependencies."""
    wallet_bp.mysql = mysql
    return wallet_bp


@wallet_bp.route('/wallet')
def wallet():
    """View wallet balance and transactions."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    user_id = session['user_id']
    balance = get_wallet_balance(wallet_bp.mysql, user_id)
    transactions = get_wallet_transactions(wallet_bp.mysql, user_id)
    
    return render_template('wallet.html', balance=balance, transactions=transactions)


@wallet_bp.route('/add_funds', methods=['POST'])
def add_funds_route():
    """Add funds to wallet."""
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))

    try:
        amount = float(request.form['amount'])
        user_id = session['user_id']
        
        success, error_msg = add_funds(wallet_bp.mysql, user_id, amount)
        
        if success:
            flash(f'Successfully added ${amount:.2f} to your wallet.', 'success')
        else:
            flash(error_msg, 'danger')
        
    except ValueError:
        flash('Invalid amount entered.', 'danger')
    except Exception as e:
        flash('An error occurred while processing your request.', 'danger')
        logger.error(f"Error adding funds: {e}", exc_info=True)
        
    return redirect(url_for('wallet.wallet'))
