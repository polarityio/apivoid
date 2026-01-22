polarity.export = PolarityComponent.extend({
    details: Ember.computed.alias('block.data.details'),
    hasDomainServerDetails: Ember.computed('details', function() {
        const serverDetails = this.get('details.totalResults.server_details');
        
        return serverDetails && Object.values(serverDetails).some(value => !!value);
    }),
    hasIpInformation: Ember.computed('details', function() {
        const information = this.get('details.totalResults.information');
        
        return information && Object.values(information).some(value => !!value);
    })
});