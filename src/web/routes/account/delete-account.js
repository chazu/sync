import { sendPug } from '../../pug';
import Config from '../../../config';

const LOGGER = require('@calzoneman/jsli')('web/routes/account/delete-account');

export default function initialize(app, authorize, csrfVerify, channelDb, userDb) {
    function showDeletePage(res, flags) {
        let locals = Object.assign({ channelCount: 0 }, flags);

        sendPug(
            res,
            'account-delete',
            locals
        );
    }

    app.get('/account/delete', async (req, res) => {
        await showDeletePage(res, {});
    });

    app.post('/account/delete', async (req, res) => {
        csrfVerify(req);

        if (!req.body.confirmed) {
            showDeletePage(res, { missingConfirmation: true });
            return;
        }

        let user;
        try {
            user = await userDb.verifyLoginAsync(req.body.username, req.body.password);
        } catch (error) {
            if (error.message === 'User does not exist' || error.message.match(/Invalid username/)) {
                showDeletePage(res, { noSuchUser: req.body.username });
            } else if (error.message === 'Invalid username/password combination') {
                showDeletePage(res, { wrongPassword: true });
            } else {
                LOGGER.error('Unknown error in verifyLogin: %s', error.stack);
                showDeletePage(res, { internalError: true });
            }
            return;
        }

        try {
            let channels = await channelDb.listUserChannelsAsync(user.name);
            let channelCount = channels.length;
            if (channels.length > 0) {
                showDeletePage(res, { channelCount: channels.length });
                return;
            }
        } catch (error) {
            LOGGER.error('Unknown error in listUserChannels: %s', error.stack);
            showDeletePage(res, { internalError: true });
        }

        try {
            await userDb.requestAccountDeletion(user.id);
        } catch (error) {
            LOGGER.error('Unknown error in requestAccountDeletion: %s', error.stack);
            showDeletePage(res, { internalError: true });
        }

        res.clearCookie('auth', { domain: Config.get('http.root-domain-dotted') });
        res.locals.loggedIn = false;
        res.locals.loginName = null;
        sendPug(
            res,
            'account-deleted',
            {}
        );
    });
}
